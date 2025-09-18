# Lab: Malicious-TLS-Investigation

## Objective 

Examine TLS traffic using Wireshark and Zeek, with a particular emphasis on analyzing certificates.

## Lab Preparation

Download the file malware-TLS.zip

SHA256: B4D6E64761D9FF2FEFE15AB25AC8CEFEFD6A9D9C770362F5C8A7ACD8BFDC754C

Install and setup Zeek & Suricata

## Lab Questions

1)   How many unique certificate subjects are in malware-TLS.PCAP?

2)   What certificate is related to the IcedID malware?

3)   What is the JA3S hash for IcedID?

4)   What domain is related to Cobalt strike?

5)   What is the JA3 hash of Cobalt Strike?

## Recap of Findings
Create a recap of findings in bullet point format and document any interesting information you found.

## Lab Step-By-Step

I am using the netlab VM to perform this lab.

`Command: cd /home/mydfir/Labs/TLS/malware`

<img width="411" height="65" alt="lab TLS malware" src="https://github.com/user-attachments/assets/c329b8e2-5e15-4bce-93a1-c2db1211b33d" />

Then we will open the malware-TLS.pcap file using Zeek and make sure to specify the local.zeek configuration.

`Command: zeek -r malware-TLS.pcap /opt/zeek/share/zeek/site/local.zeek`

We will view the contents within the x509.log file and use zeek-cut to select the field certificate.

`Command: cat x509.log | zeek-cut certificate.subject`

<img width="732" height="333" alt="Capture d’écran 2025-09-17 200331" src="https://github.com/user-attachments/assets/4b9e0090-c89b-411e-a09f-d6cc69d5d08b" />

To make the data more presentable, let's sort it out using sort, uniq -c and sort -nr
`Command: cat x509.log | zeek-cut certificate.subject | sort | uniq -c | sort -nr`

<img width="727" height="264" alt="1" src="https://github.com/user-attachments/assets/730ae265-af8e-49e2-903a-823984544f57" />

While reviewing the `x509.log` output, I noticed some interesting anomalies:

- Looking at the top certificate, it first appeared that the CN was missing. After a closer look, I realized the CN was actually placed at the **end of the subject string**. That stood out as unusual.  
- I also saw the state field (`ST`) listed as **"Some-State"** instead of a real location such as "Washington". Another anomaly worth noting.  
- Two certificates had **only the CN field filled out**. One appeared to be related to Microsoft, while the other pointed to a random domain. I flagged both of these as items of interest.

To dig deeper, I focused on the suspicious **Internet Widgits certificate**. I used the certificate fingerprint provided in `x509.log` to trace the traffic associated with it. By pivoting on that fingerprint, I could connect the odd certificate back to the specific network flows and hosts in `conn.log` and `ssl.log`.

This step allowed me to link unusual certificate behavior directly to the malware traffic in the PCAP.

## Important Note on Fingerprints

While analyzing the traffic, I worked with a **certificate fingerprint**.  
This is a unique hash value (like a digital serial number) created from the certificate itself. It tells me exactly which certificate was used in the TLS handshake.

This should not be confused with the **JA3 fingerprint**. A JA3 fingerprint is also a hash value, but instead of describing the certificate, it describes the way the client (such as a browser or malware sample) initiates the TLS connection — including things like supported ciphers and extensions.  

- **Certificate fingerprint = who the server is claiming to be (its certificate).**  
- **JA3 fingerprint = how the client is behaving during the handshake.**  

In my analysis, I specifically used the **certificate fingerprint** to trace suspicious certificates, not the JA3 values.

Let's pipe it to less to be able to read it better.

`Command: cat x509.log | less`


<img width="1309" height="410" alt="2" src="https://github.com/user-attachments/assets/bcf8c8bd-ab75-4e30-b5bc-b8a7c5145fb5" />

Add this field to zeek-cut along with the certificate.subject.

`Command: cat x509.log | zeek-cut fingerprint certificate.subject`

<img width="1318" height="332" alt="3" src="https://github.com/user-attachments/assets/76aa7822-2afe-402d-8c67-33d0b18da383" />

-Tracing Traffic Using Certificate Fingerprint-

I identified the Internet Widgits certificate with a fingerprint starting `4f1b` and ending `3493`.  
I then searched all Zeek logs for this fingerprint using `grep` to see all traffic associated with that certificate.  

This allowed me to link the certificate to specific network connections and TLS sessions, helping me pinpoint potentially suspicious or malicious activity in the PCAP.

`Command: grep '4f1b4ef43bdff8fabb8b8cb71658fbd27b88822b919824daed72ac235ead3493' *.log`

<img width="1211" height="380" alt="4" src="https://github.com/user-attachments/assets/7b147d93-f3ab-4fc8-9751-38447dba5195" />


I found that the fingerprint also appeared in `ssl.log`. From the log, I identified the destination IP `103.208.85.127` and the domain `turelomi[.]hair`.  

I looked up this domain on VirusTotal and saw that 13 security vendors flagged it as malicious. Checking the details, I confirmed it is associated with the malware family **IcedID**.  

This demonstrates how analyzing certificates can help trace and identify malicious activity during a network investigation.

<img width="1309" height="721" alt="5" src="https://github.com/user-attachments/assets/70c09ba1-5f70-4b6c-8591-1598ad9a3f57" />

Next, i will look into the ssl.log file and pipe it into less to see what fields exist.

`Command: cat ssl.log | less`

<img width="1295" height="727" alt="6" src="https://github.com/user-attachments/assets/ccaae2fb-231f-445b-9401-247408ba3b3e" />

We have the source and destination fields and the server name, but what is more important are the ja3 and ja3s fields near the end. Using zeek-cut to display the IPs, ports, server name, JA3, and JA3S fields.

`Command: cat ssl.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p server_name ja3 ja3s`

<img width="1487" height="397" alt="7" src="https://github.com/user-attachments/assets/9f39d724-a7e5-4b6b-9b7e-0d61921f12f6" />

While examining the TLS traffic, I noticed that an application on the source IP `172.18.127.129` communicated with several different IPs.  

By looking at the **JA3S hashes**, I saw that most of them were identical (`ec74a5c51106f0419184d0dd08fb05bc`), even though the IPs differed. This shows the power of JA3S: the server fingerprint stays the same even if the attacker changes IPs or domains.  

There was also one JA3S hash starting with `60a`. The domain associated with it, `ecs.office[.]com`, is likely Microsoft-related, which is expected behavior for legitimate applications.  

I then re-ran the same Zeek query without `grep` to get a full view of all TLS sessions, revealing additional interesting traffic in the SSL logs.
## Analyzing JA3S Fingerprints

`Command: cat ssl.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p server_name ja3 ja3s`

There is a lot of traffic towards 185.173.34.36 and this weird domain name which we saw in the x509 log as well that we took note of earlier.

<img width="1500" height="877" alt="8" src="https://github.com/user-attachments/assets/72a1bad5-c7aa-47c7-b74f-57898a432a15" />

This certificate had only the CN field filled out.

<img width="1375" height="786" alt="9" src="https://github.com/user-attachments/assets/cbd60a0e-a8ab-4ee2-83dd-0018db6739be" />

Searching VirusTotal for this domain, 10 vendors had flagged the domain as malicious. According to the Comments section, this appears to be a Cobalt Strike server, which is a post-exploitation tool. This is how we can use JA3 and JA3S along with Zeek to investigate and pivot to help paint a story.

<img width="1085" height="781" alt="last" src="https://github.com/user-attachments/assets/b7aedcd8-ffa9-4043-8d2d-123b461d8b42" />

## Lab Answers

1) How many unique certificate subjects are in malware-TLS.PCAP?

Answer: Malware-TLS.PCAP: Unique Certificate Subjects: 18

<img width="762" height="32" alt="a1" src="https://github.com/user-attachments/assets/929b2718-12d2-4b0f-84e4-e7966bcf9aac" />

2) What certificate is related to the IcedID malware?

Answer: Certificate: Internet Widgits Pty Ltd, Some-State, AU, localhost.

<img width="744" height="25" alt="a2" src="https://github.com/user-attachments/assets/9aaca91b-a982-45d5-8c8a-bf10da3db403" />

3)   What is the JA3S hash for IcedID?

Answer: JA3S: ec74a5c51106f0419184d0dd08fb05bc

<img width="753" height="54" alt="a3" src="https://github.com/user-attachments/assets/18a14f3a-264d-4863-a03a-23b1af09499f" />

4)   What domain is related to Cobalt Strike?

Answer: Domain: fepopeguc[.]com

<img width="555" height="121" alt="a4" src="https://github.com/user-attachments/assets/595f628d-1555-4079-acb1-9496f2b98c0e" />

5)   What is the JA3 hash of Cobalt Strike?

Answer: JA3 Cobalt Strike: 37f463bf4616ecd445d4a1937da06e19

<img width="477" height="136" alt="a5" src="https://github.com/user-attachments/assets/5a217a3e-bf0f-4259-bc16-28e660303aec" />

## Lab Takeaways

Even though most network traffic in this capture was encrypted with TLS, I was still able to extract valuable data points such as the **Server Name Identifier (SNI)**, **certificate details**, and **JA3/JA3S fingerprints**. These gave me visibility into potentially suspicious activity without needing to decrypt the traffic.  

One challenge I noted is the growing adoption of **TLS 1.3**. This version can encrypt both the SNI and certificate fields, which makes analysis more difficult. Unless the environment is configured for SSL/TLS decryption (which is uncommon due to privacy and performance concerns), defenders lose visibility into these fields.  

This exercise reinforced that while encryption limits deep inspection, careful use of metadata like JA3 fingerprints and certificates still provides strong leads for detecting malicious traffic.


