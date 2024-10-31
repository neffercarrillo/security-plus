# CompTIA Security+ (SY0-701) Complete Course & Exam (Jason Dion's Udemy Course)

## Session 1: Introduction

- Overview of what the course is.
- For IT pros or cybersec pros.
- Implement security controls on hardware, software and networks
- comptia.org
- diontraining.com
- trainer -> jason dion
- 5 domains of knowledge -> 1. general sec concepts, 2. threats, vulns and mitigations, 3. security architecture, 4. sec ops, 5. security program management and oversight
- between 70 and 90 questions.
- 3 to 5 PBQs = Performance Based Questions
- buy exam vouchers from store.comptia.org or diontraining.com/vouchers for a 10% discount
- videos -> 4 tips -> 1. turn on close captions on the videos, 2. control the speed of the video, 3. download and print the study guide, 4. join the fb group and discord support group (diontraining.com/discord)
- exam tips -> 1. there will be no trick q's, 2. pay close attn to word in bold, italics, or all uppercase, 3. answer questions based on comptia sec+ knowledge, 4. understand the key concepts of the test questions, 5. do not memorize the terms word for word, try to understand them instead
- pick target date to certify -> mid july(?) 2024

## Session 2: Fundamentals of Security

- there is a negative relationship between usability and security
- information security -> protecting the data
- information systems security -> protecting the systems that hold the data
- cia triad -> confidentiality, integrity, availability
- confidentiality -> 
- integrity -> data remains accurate
- availability -> systems are functional
- non repudiation -> guarantee an action cannot be denied by the parties involved
- authentication ->
- there is a new concept replacing the triad. the pentagon ciaNA. N is for non repudiation and A is for authentication. 
- aaa of security ->
- authentication -> verify identify
- authorization -> defines actions a user can access
- accounting -> tracking user activities
- security controls -> mitigate risk and protect cia of info systems
- 6 types of controls
- zero trust -> sec model that noone should be trusted by default
- control plane -> adaptive identity
- data plane -> focused on systems, policy
- threat -> anything that could cause harm to systems
- vuln -> weakness in the system design or its implementation
- risk = threats x vulns
- risk management find ways to minimize the likelihood/outcome of something
- confidentiality is protection of info from unauthorized access and disclosure.
- important for 3 reasons. 1 protect privacy, 2 maintain business advantage, 3 achieve regulatory compliance.
- 5 methods to maintain confidentiality #1 encryption#, 2 access controls, 3 data masking, 4 physical security measures, 5 training and awareness
- integrity helps ensure info is accurate and unchanged through it's lifecycle
- important for 3 main reasons 1 data accuracy, 2 trust, 3 system operability
- 5 methods to maintain integrity #1 hashing#, 2 digital signatures, 3 checksums, 4 access controls, 5 regular audits
- availability is used to ensure info, systems and resources are operational when needed
- 5 nines is the availability gold standard no more than 5.26 minutes of downtime in a year
- important because 1 ensure business continuity, 2 maintain customer trust, 3 upholding reputation
- use redundancy. this is duplication of components to enhance reliability. have backups.
- to maintain availability have 1 server #redundancy#, 2 data redundancy, 3 network redundancy, 4 power redundancy
- non-repudiation is providing undeniable proof in the world of digital transactions
- #digital signatures# are used for non-repudiation. is created by hashing a message and then encrypting the hash.
- important for 3 reasons 1 confirming authenticity of digital transactions, 2 ensuring integrity, 3 providing accountability
- authentication is ensures individuals are who they claim to be
- 5 methods to authenticate 1 something you know (knowledge factor), 2 something you have (posession factor), 3 something you are (inherence factor), 4 something you do (action factor), 5 somewhere you are (location factor)
- 2fa security process that requires the user to provide 2 methods of authentication
- mfa is a security process to provide multiple methods of authentication
- important to 1 prevent unauthorized access, 2 protect user data and privacy, 3 ensure validity
- authorization is permissions and privs granted to users after authentication
- important because 1 protect sensitive data, 2 maintain system integrity, 3 create more streamlined user experiences
- accounting ensures user activities are properly tracked and recorded
- important because 1 audit trail, 2 regulatory compliance, 3 forensic analysis, 4 resource optimization, 5 user accountability
- methods to do accounting 1 syslog servers, 2 network analyzers, 3 siem
- 4 security control categories are 1 technical controls, 2 managerial controls (administrative controls), 3 operational controls (procedures/day to day things), 4 physical controls
- 6 security control types are 1 preventative controls, 2 deterrent controls, 3 detective controls, 4 corrective controls (i.e. EDR), 5 compensating controls (alternative measures), 6 directive controls (policy or docs)
- gap analysis is process of evaluating the differences between an orgs current performance and it's desired state
- steps of the gap analysis 1 define scope, 2 gather data, 3 analyze the data, 4 develop a plan  to bridge the gap
- technical gap analysis evaluates orgs technical infrastructure
- business gap analysis evaluates the orgs business processes
- plan of action and milestones (POA&M) outlines measures to address vulns, includes resource allocation
- zero trust is a best practice that demands verification for everything regardless of origin
- control plane is component responsible to manage access within the org
- key elements 1 adaptive identity, 2 threat scope reduction, 3 policy-driven access control, 4 secured zones
- data plane ensures the policies and procedures are executed
- 4 components 1 subject system, 2 policy engine, 3 policy administrator, 4 policy enforcement point

## Session 3: Threat Actors (TA)

- threat actor (ta) is a an entity responsible for incidents that impact security and data protection
- ta attributes are characteristics or properties that define ta's from one another
- 5 ta types 1 unskilled attackers 2 hacktivists 3 organized crime 4 nation-state actors 5 insider threats
- shadow IT is managed and utilized w/o org approval
- honeypots designed to track and deceive potential attackers
- honeynet is a network of honeypots
- honeyfiles are decoy files
- honeytokens are fake pieces of data
- 10 motivations 1 data exfil 2 financial gain 3 blackmail 4 service disruption 5 philosophical or political beliefs (hacktivism) 6 ethical reasons 7 revenge 8 disruption or chaos 9 espionage 10 war
- ta attributes to consider are 1 internal ta 2 external ta 3 resources and funding 4 level of sophistication and capability 
- unskilled attackers (script kiddies) lack technical knowledge to develop their own tools
- hacktivists are groups that use tech skills to promote a cause
- hacktivists use defacement ddos attack doxxing steal and release sensitive data
- have high levels of sophistication
- organized crime leverage tech skills for illicit gain
  - poses a high level of capability
  - use custom malware, ransomware and sophisticated phishing
- nation-state actors groups sponsored by a government to conduct cyber ops
  - conduct false flag attacks are orchestrated with the intent to mislead investigators
  - create custom malware, use zero day
  - advanced persistent threats (apt) #long-term persistence#
  - motivated to achieve long term strategic goals
- insider threats are those which originate within the org
  - motivations 1 financial gain 2 revenge 3 unintentional
- shadow IT use of IT systems w/o org approval
- threat vectors means or pathway an attacker can get access (how)
- attack surface points where an unauth user can try to enter or extract data (where)
- threat vectors 1 messages 2 images 3 files 4 voice calls (vishing) 5 removable devices (baiting) 6 unsecure networks
- bluetooth network attack examples blueborne (on path attack?) bluesmack (denial of service)
- use deception tech (honeypots honeynets honeyfiles honeytokens) to outsmart adversaries
- use these to identify TTPs (tactic techniques and procedures)
- designed to mislead and divert attackers away from critical assets
- install honeypots in a place where it is easy for attackers to get to
- honeypots and honeynets could use to learn how your prod systems are configured
- honeytokens are useful for detecting insider threats
- other ways to mislead attackers 1 bogus dns entries 2 decoy directories 3 dynamic page generation 4 port triggering (used to hide services) 5 fake telemetry data 

## Session 4: Physical Security

- measures taken to protect tangible assets
- protective measures fencing and bollards, fences
- brute force attacks
- surveillance systems
- bypassing surveillance systems
- access controls vestibules double doored system
- piggybacking
- tailgating unauth person follows closely behind
- door locks
- access badge cloning
- rfid
- nfc
- fencing structure that encloses an area using interconnected panels
- purposes 1 visual deterrent 2 establish a physical barrier 3 delay intruders
- bollard short vertical posts made out of steel or concrete to manage or redirect vehicular traffic
- purpose 1 create physical barrier 2 visual reminder of where vehicles are not permitted to enter
- fencing is adaptable and for large perimeters
- bollards are for a specific area
- fences #prevents people#
- bollards #prevents vehicles#
- brute force attack where access is tried until you get it
- forms of brute force attacks 1 forcible entry 2 tampering w/ security devices 3 confronting security personnel 4 ramming a barrier with a vehicle
- surveillance systems setup designed to observe and report activity in an area
- 4 categories 1 video surveillance 2 security guards 3 lighting 4 sensors
- infrared sensors detect warm bodies
- pressure sensors detect weight
- microwave sensors detect movement
- ultrasonic sensors detect objects in their path
- ways to bypass surveillance 1 visual obstruction 2 blind sensors and cameras 3 acoustic interference 4 electromagnetic interference (EMI) 5 physical environment attack
- access control vestibules double door system designed w/ 2 doors to ensure that only one door can be opened at a time
- piggybacking 2 people working together. one person has authorized access and lets someone w/o authorization access. requires complicitness(?)
- tailgating unauthorized person gets access by closely following someone with authorized access. opportunistic attack.
- access badges can have rfid, nfc or magnetic strips
- door locks used to secure entryways
- biometrics have issues with acceptance and rejection rate
- false acceptance rate (FAR) user is granted access when it should not have
- false rejection rate (FRR) user is not granted access when it should have been
- equal error rate (EER) crossover error rate (CER) measure of the effectiveness of a given biometrics system (the lower this rate the better the system is)
- cipher lock is a mechanical locking mechanism with push buttons
- access badge cloning is copying data from a badge onto another card/device
- how to do it 1 scan badge 2 extract data 3 write to a new device 4 use cloned access badge
- stop this 1 implement advanced encryption in auth systems 2 implement mfa 3 regularly update security protocols 4 educate users 5 implement use of shielded wallets or sleeves 6 monitor and audit access logs

## Session 5: Social Engineering

- exploits human psychology to gain unauthorized access
- best defense is to provide security awareness training
- 6 motivational triggers to convince someone to perform an action 1 authority 2 urgency 3 social proof 4 scarcity 5 likeability 6 fear
- 4 types of impersonation 1 impersonation 2 brand impersonation 3 typosquatting 4 watering hole attacks
- pretexting use a pretext to get information from someone
- 6 types of phishing attacks 1 phishing 2 spear phishing (targeted phishing) 3 whaling (targets high profile individuals) 4 business email compromise (BEC) 5 vishing (voice phishing) 6 smishing (sms phishing)
- preventing phishing attacks anti-phishing campaign (training and performance of a simulated email campaign)
- 5 characteristics of a phishing email 1 urgency 2 unusual request 3 mismatched url in links 4 strange email addresses 5 poor grammar and spelling
- conduct an anti-phishing campaign using a free tool called phish insight by trend micro.
- fraud is a wrongful or criminal deception (you are tricked)
- identify fraud is the use of another person's information without authorization
- identity fraud (uses a card to make charges) vs identity theft (assumes identity of the victim)
- scam is a fraudulent or deceptive act or operation
- invoice scam happens when a person is tricked for paying for a fake invoice for a service or product they didn't purchase
- influence campaigns shape public opinion and behavior
- misinformation is inaccurate info shared #unintentionally#
- disinformation is #intentional# spread of false information
- other types of social engineering attacks 1 diversion theft 2 hoax 3 shoulder surfing 4 dumpster diving 5 eavesdropping 6 baiting (i.e. usb left in a parking lot) 7 piggybacking and tailgating

## Session 6: Malware

- malicious software
- threat vector method to attack (unpatched software, installing code, phishing) (how)
- attack vector means by which the attacker will gain access () (way and the how they are going to infect a system - think of a sequence of actions)
- a virus is malicious code that runs in a machine w/o a user's knowledge. #requires a user's interaction#.
- 10 types of viruses 1 boot sector (installed on the first sector of a hard drive) 2 macro virus (embedded inside another document) 3 program virus (find executables or app files to infect w/ malicious code) 4 multipartite virus (boot sector virus + program virus) 5 encrypted virus (hides itself from being detected by encrypting its malicious code or payloads) 6 polymorphic virus (advanced version of an encrypted virus. it changes the code each time it is executed) 7 metamorphic viruses (rewrites itself) 8 steal viruses (technique used to evade detection) 9 armored virus (layer of protection to confuse a person trying to analyze it) 10 hoax (attempts to scare end users into taking an action on their system. this is not really a virus)
- a worm is malicious software that can #replicate itself w/o user intervention#.
- dangers of worms 1 infect workstation and other assets 2 cause disruption to network traffic
- a trojan is malicious software disguised as a piece of desirable software
- remote access trojan (RAT) (remote control machines)
- ransomware is malicious software that blocks access to a computer system until a ransom is paid to the attacker
- how to minimize the impact of a ransomware attack 1 backup files 2 update software regularly 3 provide security awareness training to end users 4 enable multi-factor authentication
- what to do after the attack 1 never pay ransom 2 disconnect machine from the network 3 notify authorities (consult incident response plan) 4 restore data from known good backups
- botnet is a network of compromised computers or devices controlled remotely
- zombies are compromised devices in a botnet
- command and control node (C2) responsible to manage the in the botnet
- botnets are used for spam phishing campaigns ddos attacks brute force encryption schemes
- rootkit is a software designed to gain admin-level control over a computer system w/o being detected
- ring security model 3 rings (ring 3 2 1 0. 3 less permissions -> 0 more permissions.)
- kernel mode ring 0 allows system to control access to devices, drivers, sound, and monitor
- admin/root is ring 1
- dll injection technique used to run code within the address space of another process
- shim is a piece of code that is placed between two components to redirect system calls
- backdoors are used to bypass normal security and authentication functions
- remote access trojans act like backdoors
- easter egg is an insecure coding practice that was used by programmers to provide a joke to users
- logic bomb is a malicious code inserted to a program that will execute when certain conditions are met
- keylogger is a piece of software that records keystrokes that are made on a device
- they can be software-based or hardware-based
- how to protect against keyloggers 1 update and patch systems 2 invest in av or antimalware solutions 3 conduct phishing awareness training 4 implement mfa 5 encrypt keystrokes 6 conduct physical checks
- spyware designed to gather and send info about a user w/o the user's knowledge
- bloatware is software that comes pre-installed on a new device
- how to remove bloatware 1 manual removal process 2 use bloatware removal tools 3 perform a clean OS installation
- exploit technique describes the specific method by which malware infects a target
- fileless malware create a process in the system memory
- malware stages stage 1 dropper or downloader stage 2 downloader
- dropper malware type used to initiate other malware form
- shellcode
- action on objectives execute primary objectives
- concealment hide tracks of malicious activities
- malware deployment methods
- living off the land (LOL) use standard system tools
- indicators of malware attacks
- 9 indicators 1 account lockouts 2 concurrent session utilization 3 blocked content 4 impossible travel 5 resource consumption 6 resource inaccessibility 7 out of cycle logging 8 missing logs 9 published and documented attacks

## Session 7: Data Protection

- safeguard important information
- data sovereignty data stored in a country has to follow the law of the country where it is housed
- data loss prevention (dlp) sensitive info doesn't leave the company
- data classifications based on the value to the org and the sensitivity of the information (data owner decides this)
- sensitive data information that can result in the loss of an advantage to the company
- 2 data classification schemes 1 commercial business 2 government
- commercial classifications 1 public 2 sensitive 3 private 4 confidential 5 critical
- government classifications levels 1 unclassified 2 sensitive but classified 3 confidential 4 secret 5 top secret
- policies should define how data will be collected retained and disposed
- data ownership process of identifying the person for the CIA and privacy of the info assets
- data owner senior executive role that is responsible for maintaining the CIA. this is not the person who created the file. responsible for labeling the asset and responsible for the controls to protect he info asset.
- data controller entity that holds the responsibility for deciding the purposes and methods of storage, collection and usage
- data processor hired by the data controller to help with tasks
- data steward focused on the quality of the data and the associated metadata. works with the data owner.
- data custodian system admin
- privacy officer responsible for oversight of privacy-related data
- data owner should be from the business side (whomever is creating the data). IT people should not be data owners.
- 3 data states 1 data at rest 2 data in transit 3 data in use
- 6 encryption types for data at rest 1 full disk encryption (FDE) 2 partition encryption 3 file encryption 4 volume encryption 5 database encryption 6 record encryption (fields within a database record)
- 3 encryption methods for data in transit 1 ssl and tls 2 vpn 3 ipsec (authenticate and encrypt each ip packet)
- 4 protection types for data in use 1 application level 2 access controls 3 secure enclaves 4 intel software guards
- 6 data types 1 regulated data 2 trade secrets 3 intellectual property 4 legal information 5 financial information 6 human-readable data/non-human readable data
- data sovereignty digital info is subject to the laws of the country in which it is located
- general data protection regulation (GDPR)
- securing data 1 geographic restriction (geofencing) 2 encryption 3 hashing (data is converted to a fixed-character string regardless of input) 4 masking 5 tokenization (replaces sensitive data with non-sensitive substitutes known as tokens) 6 obfuscation 7 segmentation (dividing a network into separate segments) 8 permission restrictions (who has access to what)
- data loss prevention monitor the data of a system while in use, transit or rest
- endpoint dlp software installed on a workstation
- network dlp software/hardware placed at the perimeter of the network
- storage dlp software installed on a server in the data center
- cloud-based dlp system usually SaaS and it's part of a cloud service

## Session 8: Cryptographic Solutions

- cryptography study of writing and solving codes to hide true meaning
- encryption process of converting info into unintelligible info
- cipher is an algo that performs encryption or decryption
- algorithm is a #mathematical function#
- encryption str comes from the key not the algo
- key determines the output of the cipher
- use larger keys and rotate frequently
- limit key access to regular audits and monitoring
- symmetric algorithms single key (shared key). does not provide for non repudiation. 
- asymmetric algorithms two different keys (public key cryptography) one key is used to encrypt the data the other key is used to decrypt the data.
- hybrid implementation use asym encryption to securely transfer a private key that can be used w/ sym encryption
- stream cipher encrypts data single bit at a time (bit by bit encryption). uses sym algos.
- block cipher breaks input into fixed-size blocks of data and performs the encryption on each block
- symmetric algos 1 data encryption standard (DES) key length 56-bits 2 triple des (3DES) uses 3 different 56-bit keys 3 international data encryption algorithm (IDEA) 128 bit key length 4 advanced encryption standard (AES) replaced DES and 3DES 5 blowfish 32-448 key size 6 twofish variant of blowfish 7 rc cipher suite (rc4, rc5 and rc6 are used)
- rc4 is the only symmetric cipher that is a stream ciper the rest are block ciphers
- need to identify the algos as symmetric asymmetric block or stream
- asymmetric algos do not require a shared secret key
- digital signature hash digest of a message encrypted with the sender's private key
- asymmetric algos 1 diffie-hellman (key exchanges and secure key distribution) 2 rsa (factoring large prime numbers) 3 elliptic curve cryptography (ECC) (mobile devices and low-power computing devices) (is more efficient than rsa)
- hashing is a one way cryptographic function where the output is always of the same size regardless of input
- hashing algos 1 md5 2 sha-1 2 sha-2 3 sha-3 4 ripemd (RACE Integrity Primitive Evaluation Message Digest) 5 hmac (Hash-based Message Authentication Code)
- digital security standard (DSS) used for digital signatures
- pass the hash attack use hash of a user to authenticate to another system instead of the plaintext password
- birthday attack obtain a collision for a hashed value
- key stretching mitigate weaker key by increasing the time needed to crack it
- salting adding random data before hashing data
- dictionary attack attacker tries every word from a predefined list
- brute-force attacks try all password combinations available
- rainbow tables
- nonce unique number added to password-based authentication process
- limit the number of login attempts to prevent attacks on hashes
- public key infrastructure (PKI) system (hardware, software, policies) based on asymmetric encryption
- PKI system that creates asym key pairs
- certificate authority issues digital certs
- key escrow is where cryptographic keys are stored
- digital certificates
- wildcard cert allows subdomains to use the same public key cert
- subject alternate name field (SAN) is a cert that specifies additional domains and IP addresses that are going to be supported
- single-sided certs only requires the server to be validated
- dual-sided cert requires both the server and the user to be validated
- self-signed cert 
- third-party certs issued and signed by a cert authority
- root of trust
- certificate authority trusted third-party that issues digital certs
- registration authority
- certificate signing request (CSR) block of encoded text
- certificate revocation list is a list of digital certs that the CA has revoked
- online cert status protocol (OCSP) determine if a cert was revoked. this is an alternative to the list.
- ocsp stapling is alternative to ocsp
- public key pinning resists impersonation attacks
- key escrow agent
- key recovery agent restoration of a lost or corrupted key
- blockchain is a shared immutable ledger
- public ledger is a record keeping system
- smart contracts self-executing contracts
- permissioned blockchain used for business transactions
- encryption tools 1 trusted platform module (TPM) 2 hardware security module (HSM) (physical device. tamper-resistant.) 3 key management system (KMS) 4 secure enclave (co-processor integrated into the main processor of some devices)
- obfuscation
- steganography concealing a message within another
- encryption is used with stego for an extra layer of security
- tokenization substitute sensitive data w/ non-sensitive equivalents (example provided - credit cards)
- data masking (data obsfuscation) used to protect data by ensuring that it remains recognizable (example customer names are not real but it looks right for testing)
- cryptographic attacks exploit vulns in crypto systems to defeat crypto protections
- downgrade attacks (version rollback attack) use a weaker older crypto standard or protocol (example POODLE attack)
- collision attacks aims to find two different inputs that produce the same hash output (example birthday attack)
- quantum computing
- post-quantum cryptography can be implemented with today's computers
  
## Session 9: Risk Management

- process to identify analyze treat, monitor and report risk
- risk assessment freq how often does a risk assessment occur
- 4 types 1 ad-hoc (as needed) 2 recurring (on a regular interval) 3 one-time (not repeated) 4 continuous (on-going)
- risk identification recognizing a potential risk
- business impact analysis (BIA) process that evaluates the potential effects of disruption
- recovery time objective (RTO) maximum acceptable time that can elapse before lack of business function impacts the org
- recovery point objective (RPO) maximum acceptable amount of data loss measured in time
- mean time to repair (MTTR) avg time required to repair a failed component/system
- mean time between failures (MTBF) average time between failures
- risk register features key risk indicators, risk owners and risk thresholds
- risk register (risk log) records identified risks
- risk register fields 1 description 2 impact 3 likelihood/probability 4 outcome 5 level/threshold 6 cost
- risk description identify and detailed description of the risk
- risk impact potential consequences of the risk materializing
- risk likelihood/probability chance of a risk occurring 
- risk outcome
- risk level/threshold combines the impact and likelihood
- cost financial impact on the project (risk occurs or mitigating the risk)
- risk tolerance/risk acceptance willingness to deal w/ uncertainty
- risk appetite willingness to embrace or retain a specific types pf risk
- 3 types of appetite 1 expansionary 2 conservative 3 neutral
- key risk indicators (KRI) early signal of risk exposure
- risk owner person or group responsible for managing the risk
- qualitative risk analysis methods of assessing risks based on their potential impact and the likelihood of their occurrence. this method is subjective. high-level view of risk.
- quantitative risk analysis objective and numerical evaluation of risks.
- exposure factor (EF) proportion of an asset that is lost in an event
- single loss expectancy (SLE) monetary value expected to be lost in an event (Asset($) x EF)
- annualized rate of occurrence (ARO) freq with which a threat is expected to happen within a year
- annualized loss expectancy (ALE) SLE x ARO
- 4 risk management strategies 1 transfer (risk sharing. insurance.) 2 accept (not mitigating risks. exemption. exception.) 3 avoidance (altering plans) 4 mitigation
- risk monitoring tracking and identifying risk
- risk reporting communicating info about risk
- important 1 decision making 2 risk mitigation 3 stakeholder communication 4 regulatory compliance

### Exercises

Asset: 20,000
EF: 60%
ALE?

ALE = SLE x ARO
SLE = Asset x EF
ALE = Asset x EF x ARO
(# 20000 .60 (/ 1.0 5.0))
(# 20000 .60 .20)
  
## Session 10: Third-Party Vendor Risks

### Third-party Vendor Risks

- security and operational challenges introduced by external entities
 
### Supply Chain Risks

- product manufacturing
- purchase of hardware from secondary markets
- software developers and software providers
- managed service providers

### Supply Chain Attacks

- involves targeting a weaker link in the supply chain to gain access to a primary target
- chip washing
- rootkits
- semiconductors
- 4 ways to mitigate the risks of attacks 1 vendor due diligence 2 regular monitoring and audits 3 education and collaboration 4 incorporating contractual safeguards

### Vendor Assessment

- evaluate security, reliability and performance of external entities
- vendors provides goods/services to orgs
- suppliers in charge of production
- managed service providers manage IT services on behalf of your org
- penetration testing simulated cyber attack against supplier system
- contracts should have a right to audit clause
- evidence of internal audits (vendor self assessment)
- independent assessment are evaluations conducted by third-party entities
- supply chain analysis deep dive into a vendor's supply chain and assess the security and reliability of each link

### Vendor Selection and Monitoring

- due diligence rigorous evaluation of a vendor
- conflict of interest
- vendor questionnaires
- rules of engagement
- monitoring ensure chosen vendors still aligns with org's needs
- feedback loops org and vendor can share feedback with each other

### Contracts and Agreements

- basic contract establishes relationship between two parties
- service-level agreement (SLA)
- Memorandum of Agreement (MOA) formal and outline responsibilities
- memorandum of understanding is a declaration of intent
- master service agreement (MSA) blanket agreement
- statement of work (SOW) used to specify details of a project
- non-disclosure agreement (NDA) commitment to privacy.
- business partnership agreement (BPA) a step beyond the basic contract. two entities decide to pool benefits for mutual benefit.

## Session 11: Governance and Compliance

- governance is management of IT infra, policies, procedures and operations
- compliance is adherence to laws, regulations, standards and policies
- governance ensure orgs IT infra aligns w/ business objectives
- monitoring review and assess effectiveness
- revision is to update governance framework
- governance structures 1 boards 2 committees 3 government entities 4 centralized/decentralized structures
- policies 1 acceptable use policy (AUP - do's and dont's sets boundaries for appropriate use) 2 information security policies (how org protects its info assets from threats) 3 business continuity (continue critical ops during and after a disruption) 4 disaster recovery 5 incident response (plan for handling security incidents) 6 software development lifecycle (SDLC) 7 change management (implement changes in a controlled manner)
- standards provide framework for implement security measures
- standard examples 1 password standards 2 access control standards 3 physical security standards 4 encryption standards
- procedures (sequences of actions) 1 change management 2 onboard/off-boarding 3 playbooks (checklist of items to perform)
- governance considerations 1 regulatory 2 legal (contract law, intellectual property, etc) 3 industry 4 geographical
- compliance reporting is to collect and present data to demonstrate adherence to compliance requirements. can be internal or external
- compliance monitoring is the process of reviewing the orgs ops to ensure compliance. can be internal or external.
- due diligence review of orgs ops to identify potential compliance risks
- due care steps taken to mitigate risks
- attestation formal declaration that the org's processes and controls are compliant
- acknowledgment is a recognition and acceptance of compliance
- automation in compliance streamline data collection, improve accuracy and provide real-time compliance monitoring
- non-compliance consequences 1 fines 2 sanctions 3 reputational damage 4 loss of license 5 contractual impacts

## Session 12: Asset and Change Management

- acquisition process of obtaining goods and services
- procurement the full process of acquiring goods and services, including all preceding steps
- purchase options 1 corporate cc 2 individual purchase (i.e. travel w/o company credit card) 3 purchase orders (PO - formal doc that authorizes a specific purchases)
- 3 main modes of mobile asset deployment 1 bring your own device (BYOD) 2 corporate-owned, personally enabled (COPE) 3 choose your own device (CYOD)
- asset management govern and maximize value of items throughout their lifecycle
- assignment/accounting each asset needs to have owners
- classification categorize assets
- monitoring/tracking each asset is accounted for
- asset tracking monitoring location and other more details
- enumeration identify and count assets
- mobile device management (MDM) oversee employee devices
- NIST 800-88 Guidelines for media sanitization
- sanitization process of making data inaccessible from storage medium
- methods to sanitize 1 overwriting 2 degaussing (magnetic field used to disrupt magnetic domains) 3 secure erase
- destruction ensures physical device itself is beyond recovery or reuse
- certification proof that the data or hardware has been securely disposed of
- change management strategy to transition to a future state
- change advisory board (CAB) responsible for evaluation of any proposed changes
- change owner initiates the change request
- stakeholder person with vested interested in the proposed change
- impact analysis
- change management processes 1 preparation 2 vision for the change (description of the future state) 3 implementation 4 verification (measuring change's effectiveness) 5 documentation
- things we need 1 use of scheduled maintenance windows 2 backout plan 3 testing of results 4 use of standard operating procedures (SOP)
- technology implications of changes 1 allow and deny lists 2 restricted activities 3 downtime 4 service and application restarts 5 legacy applications 6 dependencies
- documenting changes 1 version control 2 proper proper documentation 3 update trouble ticket or change request

## Session 13: Audits and Assessments

- audits are systematic evaluations
- assessments detailed analysis to identify vulns and risks
- internal audits systematic evaluation of internal controls, compliance
- compliance ensures org practices adhere to standards and regulations
- audit committee group responsible for supervising orgs audit and compliance activities
- internal assessments analysis to identify risks and vulns
- self-assessment internal evals
- external audits systematic eval conducted by external entities. identifies gaps in controls and compliance.
- external assessments analysis conducted by an independent entity to identify vulns and risks
- regulatory compliance
- examination is a detailed inspection conducted externally
- independent third-party audit
- penetration testing is a simulated cyber attack that helps to assess exploitable vulns
- physical pentest find weaknesses in physical security
- offensive pentest (red teaming) involves use of attack techniques that seek to exploit vulns
- defensive pentest (blue teaming) improve incident response time, strengthen systems and enhance detection capabilities
- integrated pentesting (purple teaming) combines aspects of offensive and defensive testing into a single penetration test
- reconnaissance in pentesting initial phase of info gathering of the target system
- active reconnaissance direct engagement with the target system (i.e. nmap)
- passive reconnaissance gather information w/o direct engagement with the target system
- environment types 1 known  (testers are provided w/ details before the engagement starts. resembles insider threat scenario) 2 partially known (tester has limited information. simulate scenario when attacker has limited knowledge) 3 unknown (minimal to know info about the target system)
- attestation of findings validation or confirmation to assert accuracy and authenticity of specific information
- attestation of findings includes evidence
- software attestation validate integrity of software
- hardware attestation validate integrity of hardware components
- system attestation validate security posture of a system

## Session 14: Cyber Resilience and Redundancy

- high availability ability of a service to be continuously available by minimizing downtime
- uptime is a number of minutes of hours that a system remains online over a given period
- load balancing is distribute network across multiple computing resources
- clustering multiple computers that work as a single system (keeping app available even in a hw failure)
- redundancy - duplication of critical components or functions of a system
- data redundancy - redundant array of independent disks (RAID)
- RAID 0 - data striping to increase performance (striping)
- RAID 1 - mirrors data across two drives (mirroring)
- RAID 5 - stripes data w/ parity (needs three storage devices) (striping w/ parity)
- RAID 6 - stripes across multiple devices w/ 2 pieces of parity data (striping w/ double parity)
- RAID 10 - combines RAID 1 and RAID 0 -> mirrors data and stripes data (stripped array of mirrored arrays)
- level of resilience of RAIDS 1 failure-resistant (RAID 1 and RAID 10) 2 fault-tolerant (RAID 1, 5, 6 and 10)  3 disaster-tolerant (RAID 1 and RAID 10)
- capacity planning plan to meet future demands
- 4 aspects of capacity planning 1 people (analyze current skills and forecasting future needs for hiring and training) 2 technology (assess current resources, utilization and anticipate future) 3 infrastructure (planning for physical space and utilities) 4 process (optimize business processes to handle demand fluctuations)
- 5 power conditions 1 surges - small increase of voltage 2 spike - short transient voltage 3 sag - small  decrease in voltage 4 undervoltage event - voltage reduced and occurs for a longer period of time 5 power loss event - total loss of power
- line coniditoner overcome minor fluctuations in power
- uninterruptible power supply (UPS) provides emergency power to the system
- generator converts mechanical energy into electrical energy
- 3 varieties of generators 1 portable gas engine generator 2 permanently installed generator 3 battery inverter generators
- power distribution center (PDC) is a central hub where power is received and then distributed to all systems in the data center
- data backups create duplicate copies of digital info to protect it against data loss corruption or unavailability
- onsite backup data is located in the data center 
- offsite backup data is located at geographically separate locations
- backup frequency consider orgs RPO
- encryption on backups
- data at rest encryption
- data in transit encryption
- snapshots are point in time copies of the data capture
- recovery used to regain access to data in the event of data loss
- replication real-time copies of the data
- journaling maintains record of every change made to an orgs data over time
- continuity of operations plan ensure orgs recover from a disruptive events or disasters
- business continuity plan (BCP) addresses responses to response events
- disaster recovery plan (DRP) subset of BCP. focuses on how to resume operations.
- bcp handles an incident
- drp handles a disaster
- redundant site is an alternative site for backup
- hot site is a fully equipped backup facility. very expensive.
- warm site is a partially equipped backup site that can become operational within days of a primary site disruption
- cold site is a site with no immediate equipment or infrastructure. 
- mobile site uses independent and portable units like trailers or tents to deliver recovery capabilities
- virtual site uses cloud based environments
- virtual hot site, virtual warm site, virtual cold site
- platform diversity
- resilience testing
- recovery testing
- tabletop exercise is a simulated discussion to improve crisis readiness w/o deploying resources
- failover test verifies system transition to a backup
- simulation is a computer generated representation of real world scenarios
- parallel processing replicates data and processes onto a secondary system. check reliability and stability of the secondary setup.

## Session 15: Security Architecture

### Security Architecture

- cloud computing delivery of computing services over the internet

### On-premise versus the Cloud

- responsibility matrix division of responsibilities between the cloud service provider and the customer
- third-party vendors provide specialized services
- hybrid solutions combine on prem and cloud services
- on prem solutions computing infra physically located on site at a business
- things to consider when deciding on cloud services 1 availability 2 resilience 3 cost 4 responsiveness 5 scalability (system's ability to meet growing demand) 6 ease of deployment 7 risk transference 8 ease of recovery 9 patch availability 10 inability to patch 11 power 12 compute (amount of computational resources that a customer can use)

### Cloud Security (Risks?)
  
- shared physical server vulns
- inadequate virtual env security
- user access management
- lack of up-to-date security measures
- single points of failure
- weak authentication and encryption practices
- unclear policies
- data remnants

### Virtualization and Containerization

- virtualization allows emulation of servers
- containerization light weight alternative to virtualization
- hypervisor manages distribution of server's resources
- types of hypervisor type 1 bare metal or native type 2 operates within a standard OS
- type 1 is faster and more efficient than type 2
- containers are separated from each other but shares the host machine's kernel
- vm threats 1 virtual machine escape 2 privilege escalation 3 live migration of vms 4 resource reuse 
- vm security 1 update os 2 ensure each vm has av installed 3 good strong pws and good policies

### Serverless

- responsibility of managing servers dbs and application logic is shifted away from developers
- can offer 1 cost savings 2 automatic scaling 3 developers can focus on developing
- challenges/risk 1 vendor lock-in 2 lack of best practices

### Microservices

- software architecture where large apps are broken down into smaller independent services
- advantages 1 scalability 2 flexibility 3 resilience 4 faster deployment and updates
- challenges 1 complexity 2 data management 3 network latency 4 security 

### Network Infrastructure

- physical separation/air gapping protect sensitive info isolated from other networks by physically disconnecting it from other networks
- logical separation creates boundaries within a network (i.e. vlan)

### Software-Defined Network (SDN)

- improve performance and monitoring
- separates the network into 3 distinct planes
- planes 1 data plane (forwarding plane. handles packets.) 2 control plane (brain of the network. centralized.) 3 application plane (where all network apps interacting w/ the SDN controller reside)

### Infrastructure as Code (IaC)

- infrastructures are defined in code files that can be tested and audited
- snowflake system is a config/build that is not consistent
- idempotence ability of an operation to produce the same results as many times as it is executed
- benefits 1 speed and efficiency 2 consistency and standardization 3 scalability 4 cost savings 5 auditability and compliance
- challenges 1 learning curve 2 complexity 3 security risks

### Centralized vs Decentralized Architectures

- centralized system where all computing functions are managed from a single location/authority
- benefits of centralized 1 efficiency and control 2 consistency 3 cost and effectiveness
- risks of centralized 1 single point of failure 2 scalability issues 3 security risks
- decentralized distributes the computing functions across multiple systems or locations
- benefits of decentralized 1 resiliency 2 scalability 3 flexibility
- risks of decentralized 1 security risks 2 management challenges 3 data inconsistency

### Internet of Things (IoT)

- network of physical items w/ embedded systems that enables connection and data exchange
- hub is the central point connecting all IoT devices
- smart devices objects w/ computing capabilities and internet connectivity
- wearables subset of smart devices
- sensors detect changes in the environment and transform them into analyzable data
- risks 1 weak defaults 2 poorly configured network services

### ICS and SCADA

- industrial control systems (ICS) used to monitor and control industrial processes
- distributed control systems (DCS)
- PLC
- SCADA type of ICS used to monitor and control geographically dispersed industrial processes
- risks 1 unauthorized access 2 malware attacks 3 lack of updates 4 physical threats
- how to secure 1 strong access control 2 update and patch 3 firewall and IDS 4 regular security audits 5 employee training

### Embedded Systems

- specialized computing component
- real time operating system (RTOS) ensures data processing in real time
- vulns 1 hw failure 2 software bugs 3 security vulns 4 outdated systems
- how to secure 1 network segmentation 2 wrappers (show only the entry and exit points of the data when traveling between networks) 3 firmware code control (secure coding practices, code reviews, and automated testing) 4 inability to patch 

## Session 16: Security Infrastructure

### Security Infrastructure 

- combination of hardware software and policies orgs use to keep their data secure

### Ports and Protocols

- port is a logical comm endpoint that exists on your device
- ports are inbound or outbound
- inbound ports waiting for connections
- outbound ports created in order to call out to a server
- port range -> 0 - 65,535
- well-known ports -> 0 - 1023
- registered ports -> 1024 - 49151 (have to be used by vendors and need to be registered with IANA)
- dynamic and private ports -> 49152 - 65535
- protocol defined set of rules that govern communication
- port number, protocol used, tcp/udp support, basic description
- 21, ftp (file transfer protocol), tcp, used to transfer files from host to host
- 22, ssh/scp/sft, tcp
- 23, telnet, tcp
- 25, smtp (simple mail transfer protocol)
- 53, dns (domain name system), tcp/udp
- 69, tftp (trivial file transfer protocol), udp
- 80, http, tcp
- 88, kerberos, udp, network auth protocol
- 110, pop3, tcp
- 119, nntp, tcp
- 135, rpc, tcp/udp
- 137/138/139, netbios, tcp/udp
- 143, imap, tcp
- 161, snmp, udp
- 162, snmp trap, udp
- 389, ldap, tcp
- 443, https, tcp
- 445, smb, tcp
- 465/587, smtps, tcp
- 514, syslog, udp
- 636, ldaps, tcp
- 993, imaps, tcp
- 995, pop3s, tcp
- 1433, mssql, tcp
- 1645/1646, radius, tcp
- 1812/1813, radius, udp
- 3389, rdp, tcp
- 6514, syslog tls, tcp

### Firewalls

- monitor and control traffic based on predefined rules
- screened subnet (dual-homed host)
- firewall types 1 packet filtering (checks packet headers. layer 4 fw) 2 stateful (tracks state of connections that go in/out of the network) 3 proxy (intermediary between internal and external connection) 4 kernel proxy (5th gen firewall. full inspection across all layers)
- next-generation firewall (ngfw) -> conducts deep packet inspection, are fast, full-stack visibility, integrates w/ other security products. single engine.
- unified threat management (utm) -> conduct multiple security functions in a single appliance. these are a single point of failure. lower upfront cost, maintenance and power consumption. easier to install and configure. full integration. separate individual engines. 
- web application firewall (waf) -> focuses on the inspection of http traffic. 

### Configuring Firewalls

- access control list (acl) -> rule that permits traffic through a particular interface
- include a deny all rule at the end of the acl

### IDS and IPS

- network intrusion detection system (nids) responsible for detecting network access/attacks
- there are nids, hids and wids (wireless intrusion detection system)
- wids detects attempts to cause a dos on a wireless network
- signatured-based ids analyze traffic based on defined signatures
- pattern matching -> nids, wids
- stateful matching -> hids
- anomaly based/behavioral based -> analyzes traffic and compares a a baseline
- intrusion prevention system (ips) -> looks for malicious activity and takes action to stop it

### Network Appliances

- dedicated hw device designed to provide a service
- load balancer used to distribute network traffic across multiple servers
- application delivery controller (load balancer +)
- proxy server is an intermediary
- network sensor monitor detect and analyze traffic and data flow across a network
- jump server/jump box dedicated gateway to get into devices inside of different network zones

### Port Security

- network switch feature to restrict which devices can connect to a specific port based on the network interface mac address
- content addressable memory (CAM) table used to store info about mac addresses
- persistent (sticky) mac learning switch automatically learns and associates mac addresses
- 802.1x framework used for port-based auth for both wired and wireless networks
- 3 roles 1 supplicant (device/user requesting access) 2 authenticator 3 authentication server (centralized device. radius or tacacs+ server)
- radius is cross platform and tacacs+ is a cisco platform
- extensible authentication protocol (EAP) -> framework for authentication
- variants of EAP 1 EAP-MD5 2 EAP-TLS 3 EAP-TLS 4 EAP-FAST 5 PEAP (protected EAP) 6 LEAP (variant of EAP that only works on cisco-based devices)

### Securing Network Communications

- virtual private networks (vpn) extend a private network across a public network
- site-to-site vpn interconnect two sites
- client-to-site vpn connects individual devices directly to the orgs hq
- full tunnel vpn maximizes security by encrypting all traffic
- divides traffic and network requests and then routes them to the appropriate network
- split tunnels are less secure but offers better performance
- clientless vpn secure access through browse-based vpn tunnels. does not need hardware or software.
- transport layer security (tls) is an example of a clientless vpn
- transmission control protocol (tcp)
- datagram transport layer security (DTLS) udp version of TLS
- IPsec is a secure network protocol suite. provides confidentiality, integrity, authentication, anti-replay.
- 5 steps 1 request to start a key exchange 2 ike phase 3 ike phase 2 4 data transfer 5 tunnel termination
- transport mode ideal for client to site vpns.
- tunneling mode ideal for site to site vpns. increases packet size and exceed the MTU.
- authentication header (AH) provides connectionless data integrity and data origin authentication
- encapsulating security payload (ESP) provides authentication, integrity, replay protection and confidentiality

### SD-WAN and SASE

- software-defined wide area network (SD-WAN) cenrtalized control function to route traffic across the WAN
- secure access service edge (SASE) single solution for network access and security
- sase uses SDN (software-defined networking) and includes multiple services (firewalls vpns zero trust network access and CASBs)

### Infrastructure Considerations

- 1 correct placement of devices 2 security zones and screened subnets (DMZ = screened subnet) 3 understanding attack surface 4 determining connectivity methods 5 understanding device attributes (Active (IPS) vs passive (IDS)/in-line (on path/influence block traffic) vs tap or monitored (outside of path/listen to network activity)) 6 configure failure mode (fail open (allow all traffic w/o inspection) vs fail closed (blocks all traffic))

### Selecting Infrastructure Controls

- control is a protective measure to reduce potential risk
- key principles 1 least privilege 2 defense in depth 3 risk-based approach 4 lifecycle management 5 open design principle (ensures transparency and accountability)
- methodology to select controls 1 assess current state 2 conduct gap analysis 3 setting clear objectives 4 benchmarking (compare orgs against industry best practices) 5 conduct a cost-benefit analysis 6 ensure stakeholder involvement 7 implement monitoring and feedback loops
- best practices to select controls 1 conduct a risk assessment 2 align control selection with establish framework or standard 3 customize framework controls 4 emphasize stakeholder engagement and training

## Session 17: Identity and Access Management (IAM) Solutions

### Identity and Access Management (IAM) Solutions

- ensures right access for the right people at the right times

### Identity and Access Management (IAM)

- four main processes 1 identification 2 authentication 3 authorization 4 accounting/auditing
- identification users claims an identity
- authentication verifying the identity of a user
- authorization what permissions the user has
- accounting/auditing tracking and recording user activities
- privisioning process of creating new user accounts
- deprovisioning process of removing access rights
- identify proofing process of verifying the identity of the user before the account is created
- interoperability ability of different programs work together
- attestation process of validating that user accounts and access rights are correct and up to date
 
### Multifactor Authentication

- security system that requires more than one method of authentication
- 5 factors 1 knowledge (something that you know) 2 posession (something you have) 3 inherence (something you are) 4 location (somewhere you are) 5 behavior (something you do)
- 3 types 1 single-factor (use single auth factor) 2 two-factor (uses two factors) 3 multi factor (uses two or more factors)
- passkeys passwordless authentication

### Password Security

- password's ability to resist guessing and brute force attack
- 5 characteristics of strong passwords 1 length 2 complexity (which caracter sets can you use) 3 reuse (can't reuse passwords when setting up a new one) 4 expiration 5 age
- use password managers. 
- passwordless authentication provides more security
- biometric authentication
- hardware token
- one-time password (OTP)
- magic link (link automatically logs a user into a website)
- passkey integrates with the browser or OS
  
### Password Attacks

- types of attack brute force dictionary spraying hybrid
- brute force attack tries every combination of characters
- dictionary attack uses a list of commonly used passwords and trying them all
- spraying attack form of bruteforcing attack tries a small number of passwords against a large number of users
- hybrid attack blends brute force and dictionary techniques

### Single Sign-On

- allows user to access multiple apps by logging in only once w/ a single set of creds
- identity provider (IdP)
- 3 used protocols 1 LDAP (distributed directory services) 2 OAuth (Open Authorization. token based authentication and authorization. commonly used for authentication and authorization in restful apis) 3 SAML (security assertion markup language. allows services to separate from identity providers. logging users based on sessions.)
- LDAPS is secure LDAP.

### Federation

- linking of electronics identities and attributes
- use same username/pw to log in to multiple systems
- uses trust relationships between different systems
- 6 step process 1 login initiation 2 redirection to an IdP 3 authenticating the user 4 generation of an assertion 5 returning to a service provider 6 verification and access
  
### Privileged Access Management

- privileged access management (PAM) solution that helps orgs restrict and monitor privileged access
- 3 components 1 just in time permissions (granted only when needed) 2 password vaulting (store and manage password in a secure environment) 3 temporal accounts (provides time limited access to resources) 4 

### Access Control Models

- 5 primary models 1 mandatory (mac. uses security labels. reserved for high sec systems) 2 discretionary (dac. resource's owner determines which users can access each resource) 3 role-based (rbac. assigns users to roles and uses these roles to grant permissions) 4 rules-based (rbac. admins security policies to all users) 5 attribute (abac. uses object characteristics to determine access)
- time-of-day restrictions
- principle of least privilege
- permission or authorization creep -> users getting more permissions as the user changes from roles within an organization

### Assigning Permissions

- admin and user accounts
- principle of least privilege
- microsoft account
- user account control (uac)
- file and folder permissions

## Session 18: Vulnerabilities and Attacks

### Vulnerabilities and Attacks

- vuln is a weakness or a flaw
- attacks are actions carried out to exploit vulns

### Hardware Vulnerabilities

- flaws inherent in a device's physical components
- firmware provides low level control for the device's hardware
- end of life systems hw/sw products that have reached the end of their lifecycle
- legacy systems outdated hw/sw
- unsupported systems
- unpatched systems 
- hardware misconfiguration devices settings are not optimally set up
- hardening tightening security of a system
- patching updating the sw of a device
- configuration enforcement ensure all devices are configured well
- decommissioning system is retired and removed from the network
- isolation limit the potential damage that might occur
- segmentation used to divide the network into segments

### Bluetooth Vulnerabilities and Attacks

- bluetooth wireless tech std to exchange data w/o an internet connection in short distances
- insecure device pairing devices establish a connection w/o proper authentication
- device spoofing impersonates a legitimate device
- on-path attack exploits vuln in protocol to intercept and alter comms between devices
- bluejacking sends unwanted messages to a bluetooth device (spam)
- bluesnarfing steal info
- bluebugging take control of device bt function
- bluesmack denial of service attack
- blueborne spreads through the air 

### Mobile Vulnerabilities and Attacks

- sideloading install apps from unofficial sources
- jailbreaking/rooting gives the users escalated privileges on their devices
- insecure connection methods
- mobile device management (MDM) conduct regular patching of devices and enforces config management

### Zero-day Vulnerabilities

- vuln discovered or exploited before the vendor knows about it and has a patch for it 

### Operating System Vulnerabilities

- unpatched systems have not been updated w/ latest patches
- zero-day vulns unknown to developers that have not been publicly disclosed
- misconfiguration system are not properly configured
- data exfiltration unauth data transfers to an external location
- malicious updates 

### SQL and XML Injections

- injections attacker sends malicious data to a system
- sql commands select insert delete update
- code injection insertion of additional information through a form
- xml used by web apps for data exchange
- xml bomb (billion laughs attack) file expands to exponential sizes. DoS attack.
- xml external entity (XXE) attack

### Conducting an SQL Injection

- Not needed for the exam. This is here just for awareness.

### XSS and XSRF

- cross-site scripting (XSS) injects malicious script into a trusted site
- xss game area -> https://xss-game.appspot.com/
- reflected or non-persistent XSS
- persisent XSS allows an attacker to insert code into the backend database
- document model (DOM) XSS exploits the client's web browser using client-side scripts
- session management uniquely identify a user across different actions
- cookie file that contains user data
- session cookies are non-persisent
- persisent cookies are stored in the browser cache
- session hijacking spoofing attack disconnects a host and then replaces it with itself
- session prediction attackers attempts to predicts the session token
- cross-site request forgery (XSRF) exploit a session started on another site within the same browser
- how to protect against XSRF
- use user-specific tokens in all form submissions
- add randomness and prompt for additional information
- require user to enter their current password when changing their password

### Buffer Overflow

- data exceeds allocated data
- buffer is a temporary storage area
- stack reserved area of memory
- smashing the stack attacker executed their malicious code by oeverwriting the return address
- address space layout randomization (ASLR) randomizes memory addresses making buffer overflow attacks harder

### Race Conditions

- the outcome depends on the timing of events not matching the events developer's intended order
- multiple threads write to the same variable at the same location
- dereferencing code attempts to remove the relationship between a pointer and the thing that pointer was pointing to
- example -> dirty COW
- time of check (TOC) attacker can alter a system resource after an application checks its state but before the operation is performed
- time of use (TOU) attacker can change a system between the time it is checked and the time it is used
- time of evaluation (TOE) manipulation of data or resources during the time window when a system is making a decision
- mutex mutually exclusive flag so one thread can be processed at a time
- deadlock lock remains in place and the lock is never removed

## Session 19: Malicious Activity

### Malicious Activity

- intro
- discuss ddos, amplified ddos and reflected ddos
- domain name server attacks
- directory traversal attacks
- privilege escalation attacks
- replay attacks
- session/cookie/session key hijacking
- malicious code injection attacks
- indicators of compromise (ioc)

### Distributed Denial of Service

- used to describe an attack that attempts to make a computer or server's resources unavailable
- flood attack send more packets to a host that it can handle
- ping flood uses ping (icmp echo request)
- syn flood initiates multiple tcp sessions but never complete the 3-way handshake
- flood guards block requests
- timeout half-open requests
- intrusion prevention also helps
- permanent denial of services exploits a vuln and flashes device firmware
- fork bomb creates large number of processes are created. this is not a worm.
- distributed denial of service (ddos) use hundreds of machines to attack a single server
- dns amplification attack allows attacker to initiate dns requests from a spoof ip address to flood a website
- blackhole/sinkhole
- intrusion prevention
- elastic cloud infrastructure

### Domain Name System (DNS) Attacks

- dns translates domain names into ip addresses
- dns cache poisoning (dns spoofing) corrupting the dns cache data of a dns resolver with false info
- utilize dnssec to add a digital signature to the orgs dns data
- dns amplification attack overloads a target system w/ dns response traffic by exploiting the dns resolution process
- limit the size of dns responses
- dns tunneling uses dns protocol to encapsulate non dns traffic over port 53
- domain hijacking altering domain name's registration w/o the original registrant's consent
- use domain registry lock
- dns zone transfer attack mimics authorized system to request and obtain the entire dns zone data for a domain

### Directory Traversal Attacks

- injection attack that allows access to commands, files, and directories, either connected to web document root directory or not
- can also use %2e%2e%2f for ../
- file inclusion download files from a location or upload an executable or script file to open a backdoor
- remote file inclusion attacker tries to execute a script
- local file inclusion attacker tries to add a file that already exists (uses directory traversal)

### Execution and Escalation Attack

- arbitrary code execution vuln that allows an attacker to run a code or module that exploits a vuln
- remote code execution type of arbitrary code exec that allows an attacker to transmit code from a remote host
- privilege escalation user accesses or modifies specific resources that they are not entitled to normally access
- vertical privilege escalation from normal user to higher level user
- horizontal privilege escalation from one user to another of generally the same level
- rootkit class of malware that modifies system files, often at the kernel level, to conceal its presence
- ring model ring 0 - 3
- kernel model rootkit operates at ring 0
- user mode rootkit 

### Replay Attacks

- network-based attack that involves maliciously repeating or delaying valid data
- session hijack
- replay attack attacker intercepts data and retransmits later
- session tokens and mfa to prevent replay attack
- use the latest security protocols like WPA3

### Session Hijacking

- session management enables web apps to identify users
- cookies allow web apps to retain info about users
- session cookies are non persistent
- persistent cookies live in the browser's cache
- session hijacking spoofing attack where the host is disconnected and replaced by the attacker
- session prediction attacker attempts to predict the session token to hijack that session
- cookie poisoning modifying the contents of a cookie to be sent to a client's browser and exploit the vuln in an application

### On-Path Attacks

- attack where the pen tester puts their workstation logically between two hosts during the communication
- replay valid data is captured by the attacker and then repeated
- relay attacker insert themselves in the communication
- ssl stripping tricking the encryption application with an http connection instead of an https connection
- downgrade attack attacker attempts to have a client or server abandon its higher security mode to a lower security mode

### Injection Attacks

- ldap protocol for access and maintenance of distributed directory
- ldap injection attack ldap statements are fabricated
- input validation and input sanitization
- command injection attacker is able to execute arbitrary shell commands via a vulnerable web app
- input validation
- process injection executing arbitrary code in the address space of a separate live process
- endpoint security solutions, security kernel module and least privilege

### Indicators of Compromise (IoC)

- data pieces that detect potential malicious activity
- account lockout account has been locked out due to failed login attempts
- concurrent session usage one user having multiple active sessions
- blocked content users try to access or download content that security measures have prevented
- impossible travel suspicious logins occur from distant locations in an impossible timeframe
- resource consumption unusual resource spikes can signal a compromise
- resource inaccessibility inability to access files, databases or network services
- out of cycle logging log entries that happen at unusual times
- missing logs attackers delete logs to cover their tracks
- articles or docs on security breach attackers may announce their hacks

## Session 20: Hardening

### Hardening

- process of enhancing the security of a system
- 1 conf management 2 restricting apps 3 unnecessary services 4 trusted operating systems 5 updates and patches 6 patch management 7 group policies 8 SELinux (Security-Enhanced Linux) 9 data encryption levels 10 secure baselines

### Changing Default Configurations

- default passwords
- disable unneeded ports and protocols on the system
- check for any open ports on the devices

### Restricting Applications

- least functionality configure workstation to only provide needed apps and services
- secure baseline image standardized workstations setup
- allowlisting permits approved applications (most secure method. more difficult to manage.)
- blocklisting prevents listed applications (less secure than allowlisting. easier to manage.) 

### Unnecessary Services

- services are background applications

### Trusted Operating Systems (TOS)

- Trusted Operating Systems (TOS) provides a secure computer environment that rely on mandatory access control
- integrity-178B posix-based operating system
- evaluation assurance level (EAL) 6
- common criteria standard
- eal 1 to eal 7
- mandatory access control (MAC) access permissions are determined by a policy defined by the sys admin and enforced by the OS
- SELinux set of controls installed on top another linux distro (EAL 4+)
- Trusted Solaris uses MAC
- enhances security using microkernels. this minimizes the attack surface.
- Windows 7+ eal 4 and eal 4+
- eal 4 the OS was carefully designed, tested and reviewed offering good security assurance

### Updates and Patches

- patch management - manual or automated
- hotfix patch that solves a security issue
- update provides the system with additional functionality
- service pack includes all hotfixes and updates since the release of the operating system
- patch management process/program(?) 1 assign a dedicated team to track 2 establish automated system-wide patching 3 include cloud resources 4 triage all patches 5 have a lab environment to test all urgent and important patches 6 maintain detailed logs 7 establish process for evaluating firmware updates 8 develop process for deploying approved urgent patches to prod 9 assess non-critical patches for combined rollout

### Patch Management

- planning testing implementing and auditing of software patches
- 4 steps 1 planning 2 testing 3 implementation (use patch rings. patch rings increase the amount of devices as you move from rings 1 through x) 4 auditing
- cisco ucs manager

### Group Policies

- rules or policies applied to users/accounts
- baselining is the process of measuring changes. helps establish what normal is.

### SELinux

- mandatory access control (MAC)
- context-based permissions defined by properties for a given file or process
- SELinux and AppArmor are both context-based permissions
- discretionary access control (DAC) each object has a list of entities that are allowed to access it
- SELinux does not allow DAC. it relies on MAC.
- three main contexts - user role and type
- user defines who can access
- role what roles can access
- type groups objects together that have similar security requirements or characteristics
- (fourth context)level used to describe the sensitivity level of a given file, directory, or process
- 3 modes disabled enforcing permissive
- disabled - turned off
- enforcing - all policies are enforced
- permissive - enabled but security policies are not enforced
- 2 types of policies - targeted strict
- targeted -> higher levels of protection
- strict -> enforces MAC on everything on your system

### Data Encryption Levels

- process of converting data into a secret code to prevent unauthorized access
- full-disk encryption
- partition encryption
- volume encryption
- file-level encryption -> example -> gpg (gnu privacy guard)
- database encryption -> example -> sql server transparent data encryption (TDE)
- record-level encryption

### Secure Baselines

- standard set of security configurations
- 1 prepare secure image
- 2 deploy secure baseline across enterprise
- 3 maintain the secure baseline on all assets

## Session 21: Security Techniques

### Security Techniques

- wireless infrastructure security
- wireless security settings
- application security
- network access control (NAC)
- web filtering and dns filtering
- email security
- endpoint detection and response (EDR)
- user behavior analytics
- selecting secure protocols

### Wireless Infrastructure Security

- wireless access points (WAP). placement is important. place them near the center of the facility. also place them in a higher location.
- extended service set (ESS) multiple WAPs working together to create extended coverage eare
- interference co-channel two WAPs are using the same frequency bands/channels
- interference adjacent channel channels selected for adjacent wireless points don't have enough space between channels(?)
- always select channels 1, 6 and 11 when operating in the 2.54GHz spectrum
- site survey process and planning for wireless. scan air waves.
- heat map graphical representation of the wireless coverage

### Wireless Security Settings

- wired equivalent privacy (WEEP). outdated security standard. fixed encryption key.
- 64 bits WEP key and 128 bit WEP key
- wep is insecure because of a weak 24-bit initialization vector
- wifi protected access (WPA)
- wpa improved with TKIP
- wpa insecure because lack of sufficient data integrity checks in the TKIP implementation
- wifi protected access 2 (WPA2)
- CCMP
- message integrity code (MIC)
- wifi protected access 2 (WPA3)
- simultaneous authentication of equals (SAE). provides better protection against offline dictionary attacks.
- enhanced open/opportunistic wireless encryption (OWE). guards against eavesdropping.
- uses AES GCMP (Galois Counter Mode)
- management protection frames
- authentication, authorization and accounting (AAA) protocols
- remote authentication dial-in user service (RADIUS)
- terminal access controller access-control system plus (TACACS+). allows for more granular control.
- TACACS+ uses tcp and encrypts comms
- extensible authentication protocol (EAP) -> universal authentication framework
- protected extensible authentication protocol (PEAP). secure EAP within an encrypted TLS tunnel. requires certificate on client and server.
- extensible authentication protocol-tunneled transport layer security (EAP-TLS). requires certificate on the server side only.
- extensible authentication protocol-flexible authentication via secure tunneling (EAP-FAST). developed by cisco. developed to replace LEAP.

### Application Security

- input validation. serves as quality control for data. validation rules.
- secure cookies. transmitted over https. 
- static code analysis (SAST). debugging and review of code before the program is run. software does this. when done by a human it is called a manual code review.
- dynamic code analysis (DAST). analyzes an application while it is running. fuzzing and stress testing.
- code signing. used to confirm the identity of the developer.
- sandboxing. isolate running programs.

### Network Access Control (NAC)

- scans devices for their security status before granting network access.
- persisent agent. installed on the endpoint.
- non-persistent agent. captive portal.
- ieee standard 802.1x.
- you can use different factors to allow access. time, location, role-based (adaptive NAC), rule-based (if this then that) 

### Web and DNS Filtering

- web filtering. restrict or control content a user can access on the internet.
- agent-based web filtering. software installed on the endpoint does the web filtering.
- centralized proxy. server that acts as an intermediary.
- url scanning. analyze a website's url to determine its safety.
- content categorization. websites are categorized.
- block rules.
- reputation-based filtering. blocking or allowing websites based on their reputation score.
- dns filtering. block access to websites by preventing the translation of specific domain names to their corresponding IP addresses.

### Email Security

- dkim. digital signature. receiver can check if email was sent by the sender.
- spf. sender policy framework. verify if email was sent from an authorized ip address.
- dmarc. email-validation. detects and prevents email spoofing.
- email gateway. server/system that serves as the entry and exit point for emails. can be on-prem, cloud or hybrid.
- spam filtering. 

### Endpoint Detection and Response (EDR)

- edr (endpoint detection and response). monitor endpoint and network events. provides incident data. focused on endpoints.
- file integrity monitoring (FIM). verifies current file state and a known good baseline.
- xdr (extended detection and response). integrates multiple detection technologies into a single platform. extends beyond endpoints. correlates data among multiple security layers.

### User Behavior Analytics (UBA)

- detect security threats using big data and machine learning
- user and entity behavior analytics (UEBA). adds monitoring of entities. an entity is beyond a user. includes servers, devices, etc.
- benefits 1 early detection of threats 2 insider threat detection 3 improved incident response 

### Selecting Secure Protocols

- protocol. rules or procedures for transmitting data.
- port. identifies specific processes or services in a system. well-known (0-1023), registered (1024 to 49151), dynamic or private ports (49152 to 65535).
- transport method. the way data is moved. tcp or udp.

## Session 22: Vulnerability Management

### Vulnerability Management

- process to identify, prioritize and mitigate vulns

### Identifying Vulnerabilities

- spotting and categorizing weaknesses
- vuln scanning. automated method to discover potential vulns. 
- application security. safeguard software across its lifecycle.
- static analysis. analyze source code w/o running it.
- dynamic analysis. evaluate app as it is being run.
- package monitoring. ensures libs and components are up to date.
- penetration testing. simulate a real world attack on a system.
- system and process audits. comprehensive review of policies.
- process 1 planning 2 testing (test patches and updates) 3 implementing (deploy patches) 4 auditing (verify effective patch implementation)

### Threat Intelligence Feeds

- process used to understand the threats faced by an org
- threat intel feed. data related to potential or current threats that an org faces
- open source intelligence (osint). intelligence collected from public forums.
- proprietary or 3rd party feeds. provided by commercial vendors. refined, analyzed and timely.
- info sharing orgs.
- dark web. 

### Responsible Disclosure Programs

- ethical practice to disclose info about a vuln
- bug bounty. encourage researchers to find and report vulns.
- benefits 1 increase security of the org 2 foster community collaboration 3 cost-effective

### Analyzing Vulnerabilities

- true positive. correct identification.
- false positive. vuln identified doesn't exist.
- true negative. no vuln identified.
- false negative. a vuln exists but is not identified.
- rank vulns by severity and impact.
- cvss. common vuln scoring system.
- common vulnerabilities and exposures (cve). standardized way to identify and reference known vulns.
- exposure factor (EF). metric to understand the percentage of an asset that is likely to be damaged or affected by a vuln.
- risk tolerance. risk level that an org is willing to accept.
- 6 steps 1 confirmation 2 prioritization 3 classification 4 org impact 5 exposure factor 6 risk tolerance

### Conducting Vulnerability Scans

- this is a demo of nessus.

### Assessing Vulnerability Scan Results

- demo of openvas.

### Vulnerability Response and Remediation

- identify, assess and address vulns
- patching. apply software updates.
- insurance. purchase a policy to mitigate financial losses.
- network segmentation. diving a network into smaller parts.
- compensating controls. alternative security measures. used when standard controls are not feasible.
- granting exceptions and exemptions. (Exceptions) temporary relaxes security controls. (Exemption) permanently waives controls for a specific reason.

### Validating Vulnerability Remediation

- rescanning. verify vuln elimination. id new vulns. schedule automatic rescans. use comprehensive scans. replicate initial scan conditions.
- auditing. config auditing to check for misconfigs. patch auditing to verify proper patch application.
- verification. test system to confirm the patch has the necessary effect. penetration test. user verification. feedback loops.

### Vulnerability Reporting

- process of documenting and communicating details about a security weakness
- internal reporting. comms within the org. provides details. needs to be timely.
- external reporting. comms outside the org.
- responsible disclosure reporting. disclose vulns. collab w/ the owners of the app. allow grace period to ensure they can address the issue b4 public announcement.
- vuln reports must remain confidential.

## Session 23: Alerting and Monitoring

### Alerting and Monitoring

- alerting. notify relevant personnel. 4 types. true pos. false pos. true neg. false negative.
- monitoring. observation of a system to identify intrusions. 2 types. automated monitoring. manual monitoring.

### Monitoring Resources

- system monitoring. observation of a computer system to id issues of performance.
- baseline. set of established metrics and data points for standard behavior.
- application monitoring. manage and monitor the perf and availability of software.
- infrastructure monitoring. observe physical and virtual infra.

### Alerting and Monitoring Activities

- log aggregation. collecting log data into a centralized location.
- alerting. notifications when specific events occur.
- scanning. scan system to identify problems. (nessus, openvas, qualys)
- reporting. generate reports based on collected and analyzed data.
- archiving. storing data for longer retention and future reference.
- alert response and remediation or validation. respond to alerts.
- quarantining. isolate device from the rest of the network.
- alert tuning. adjust alert parameters to improve alert relevance.

### Simple Network Management Protocol (SNMP)

- protocol for collecting and organizing info about managed devices on IP networks
- snmp commands. trap (send info to management node w/o request from the management node), set (set values), get (get values).
- granular trap message. each message is sent with a unique identifier.
- management information base (MIB). used to describe the structure of the management data.
- verbose trap message. configured to contain all the info about a given alert. takes more resources.
- three versions of snmp(v1, v2, v3).
- v1 and v2 use a community string stored in plaintext.
- snmp v3 enhancements. integrity, authentication and confidentiality.
- snmp v3 groups stuff into entities.

### Security Information and Event Management (SIEM)

- siem. solution that provides real-time analysis of security alerts that are provided by network hardware and applications.
- agent. software installed on each system to collect log data and send it to the SIEM.
- agentless. siem will directly collect data from devices using standard protocols (snmp or wmi).
- splunk. market leading.
- elastic stack (ELK). collection of free and open source tools. elasticsearch, logstash, kibana (visualization), beats (agent).
- arcsight. siem log management and analytics software.
- qradar. siem log management. created by ibm.

### Data from Security Tools

- siem. central hub for consolidation.
- antivirus. protects systems against malware, viruses, etc.
- data loss prevention (DLP). monitor and control data endpoints to prevent potential data breaches.
- IPS (prevention) and IDS (detection).
- firewalls. barrier between trusted internal network and untrusted external network.
- vuln scanners. used to identify security weaknesses in a system.

### Security Content Automation and Protocol (SCAP)

- suite of open standards that automate security tasks
- open vuln and assessment lang (OVAL). xml schema for describing the system security state
- extensible conf checklist description format (XCCDF). xml schema for developing auditing best-practice conf checklists and rules
- asset reporting format (ARF). xml schema to express info about the assets an the relationships between assets and reports.
- common conf enumeration (CCE). scheme for provisioning secure conf checks.
- common platform enumeration (CPE). scheme for identifying hardware devices, operating systems and...
- common vulns and exposures (CVE). list of records used to describe a publicly known vuln
- common vulnerability scoring system (CVSS). used to provide a numerical score to reflect the severity of a vuln.
- benchmark. config rules for products to provide a detailed checklist that can be used to secure systems to a specific baseline.

### NetFlow and Flow Analysis

- full packet capture (FPC). captures entire packet. takes a lot of resources.
- flow analysis. flow collector. records metadata and statistics rather than capturing each packet. does not provide the content.
- netflow. cisco developed means of reporting flow analysis.
- IP Flow Information Export (IPFIX). defines traffic flows based on shared packet characteristics.
- zeek. monitors network like a sniffer but only logs full packet capture data of potential interest.
- multi router traffic grapher (MRTG). graphs showing traffic flows through the network interfaces of routers and switches

### Single Pane of Glass (SPOG)

- single pane of glass. central point of access for all info and tools.
- benefits 1 simplifies security management 2 monitor environment for suspicious activity 3 track progress of incident response 4 improve efficiency of soc 5 improves collaboration and comms 6 simplifies compliance with regulatory compliance
- defining the requirements. info tools and systems that the sec team needs.
- identifying and integrating data sources.
- customizing the interface.
- developing standard operating procedures and documentation.
- continuously monitor and maintain the solution.

## Session 24: Incident Response

### Incident Response

- structured approach to manage and mitigate security incidents

### Incident Response Process

- incident. violating an explicit or implied security policy.
- four phases according to nist 800-61.
- incident response procedures. guidelines for handling security incidents.
- use the 7 phase model for the exam.
- preparation. strengthening systems and networks to resists attacks. getting ready for future incidents.
- detection. identifies security incidents.
- analysis. examination and evaluation of the incident.
- containment. limit the scope of the incident. i.e. separate endpoint from the network.
- eradication. aims to remove malicious files.
- recovery. restore systems to their regular state.
- post incident activity or lessons learned. happens after containment and eradication.
- root cause analysis. identify initial source of the incident. 4 steps.
- lessons learned process. documents experiences during incidents.
- after-action report. collects info about what happened.
  
### Threat Hunting

- method for finding the presence of threats not caught by regular security monitoring.
- establish a hypothesis. predict impact and likelihood. use threat modeling.
- profile threat actors and activities.
- perform log analysis.
- advisories and bulletins. info on new TTPs.
- intelligence fusion and threat data. siem and analysis platforms to spot concerns.

### Root Cause Analysis

- process to identify the initial source of the incident.
- determine initial cause.
- determine causal relationships.
- identify solutions.
- implement and track solutions.

### Incident Response (IR) Training and Testing

- training. ensure people understand processes and priorities for incident response. tailored to the role.
- testing. practical exercise of incident response procedures.
- tabletop exercise (TTX). simulates incidents within a control framework. cost effective.
- penetration test. simulates network intrusion based on threat scenarios.
- simulation. replicates real incidents for hands-on experience. simple scenarios. complex scenarios. 

### Digital Forensic Procedures

- process of investigating and analyzing digital devices
- identification. ensure the safety of the scene. identify the scope of the evidence.
- collection. process of gathering, preserving and documenting stuff.
- order of volatility. sequence in which data sources should be collected and preserved. start with most volatile resources.
- nist 800-86. collect data from system's memory. capture data from systems state. collect data from storage devices. capture network traffic and logs. collect remotely stored archive data.
- chain of custody. documented and verifiable record that handling, transfer, and preservation of evidence.
- disk imaging. bit by bit copy of a storage device.
- file carving. extract files and data fragments. useful when file metadata is missing.
- analysis. scrutinize the data.
- reporting. documenting the findings.
- legal hold. preserve all potentially relevant electronic data, documents, and records.
- electronic discovery. identifying, collect and producing electronic data.

### Data Collection Procedures

- use digital forensics methods
- use forensic toolkit (FTK, enCase)
- capture screenshots of the machine
- follow order of volatility when collecting evidence
- data acquisition. method and tools used to create a forensically sound copy of the data from a source device.
- cpu registers and cache memory
- system memory (RAM). routing tables, arp caches...
- data on persistent mass storage (hdd, sdd, flash drives)
- remote logging and monitoring data
- physical configuration and network topology
- archival media
- In Windows, HKLM\Hardware registry keys requires a memory dump to analyze. The other keys can be found in the hard disk.

### Disk Imaging and Analysis

- demo of disk imaging using DD.

## Session 25: Investigating an Incident

### Investigating an Incident

- summary of the lesson

### Investigating with Data

- security information and event monitoring system (siem). combination of multiple data sources.
- sensor. endpoint being monitored.
- sensitivity (at the sensor). how much/little will be logged.
- trends.
- alerts.
- correlation.
- log file. any file that records events in the OS.
- syslog/rsyslog/syslog-ng. logging of data into a centralized system. works in unix/linux systems.
- journalctl. displays logs from journald.
- nxlog. multiplatform log management tool.
- netflow. network protocol created by cisco. collects active ip network traffic.
- sampled flow (sflow). open source version of netflow.
- internet protocol flow information export (IPFIX). universal standard of export for internet protocol flow info from routers and other devices.
- metadata. data that describes other data. data about data.

### Dashboards

- graphical display.
- splunk. large scale data platform. siem.

### Automated Reports

- computer-generated report.
- <<think about having a  automated security incident report.>>
- executive summary condenses the contents of the reports.

### Vulnerability Scans

- vuln scan. generates scan reports automatically. review the report produced by the scan for confirmation.

### Packet Captures

- gathers all data sent to or from a specific network device
- snippets from firewall logs to figure out attacks.

### Firewall Logs

- snippets from firewall logs to figure out attacks.
- logs can be different base on the layer they operate on (layer 7 = application -> web server).

### Application Logs

- snippets for review.

### Endpoint Logs

- snippets for review.

### OS-specific Security Logs

- snippets for review.
- these exercises will be mainly to identify password cracking methods.

### IPS/IDS Logs

- snippets for review.

### Network Logs

- snippets for review.
- arp spoofing example.
  
### Metadata

- data about data.
- md5/sha256. unique digital fingerprint for files.

## Session 26: Automation and Orchestration

### Automation and Orchestration

- summary
- automation. individual tasks.
- orchestration. multiple automated tasks.
- SOAR. security, orchestration, automation and response.
- soar is a siem 2.0.
- soar is used for incident response.
- playbook. checklist of actions for a specific incident response.
- runbook. automated versions of playbook with human interaction points.
  
### When to Automate and Orchestrate

- complexity. apply to repetitive tasks.
- cost.
- watch out for single points of failure
- technical debt. cost and complexity of poorly implemented software needing future adjustments
- ongoing supportability.
- automation and orchestration should be created for tasks that are repeatable and stable

### Benefits of Automation and Orchestration

- 7 main benefits.
- increase efficiency and time savings.
- enforcing baselines.
- implementing standard infrastructure configurations.
- scaling in a secure manner
- increasing employee retention
- increasing reaction times
- being a workforce multiplier

### Automating Support Tickets

- automation. process of using tech to perform tasks with minimal human intervention.
- ticket creation. automatic generation of tickets when users or customers enter issues.
- ticket escalation. ensures high-priority issues are addressed promptly.

### Automating Onboarding

- user provisioning.
- resource provisioning.

### Automating Security

- security automation. uses tech to handle repetitive security tasks.
- guardrails. automated safety controls.
- security groups. cloud based server firewalls that control incoming and outgoing network traffic.
- service access management.
- manage permissions. role-based access controls (rbac)

### Automating Application Development

- continuous integration (CI). developers merge code changes frequently in one place.
- release. finalize and prepare new software or updates. enable software installation and usage.
- deployment. process of software releases to users. installing software into a new environment.
- continuous delivery (CD). maintains deployable code with automation. part of the release process and not deployment.
- continuous deployment (CD). automates the process of deploying code changes from testing to production after completion of the build stage. 

### Integrations and API

- integration. process of combining different components into one.
- application programming interface (api). protocols for integrating software.
- representational state transfer (REST). uses standard http methods.
- simple object access protocol (SOAP). uses xml format.
- soap is more robust than rest.
- soap provides higher level of security.
- curl. tool used to transfer data to a server.

## Session 27: Security Awareness

### Security Awareness

- knowledge and understanding of potential threats
- insider threat. threat that originates from individuals from within the org.
- password management. practices and tools.
- policies. documented guidelines.
- handbooks. comprehensive guides
- remote work. work from home/working from another location.
- hybrid work. combination of remote work and in office.
- culture of security. organizational mindset.

### Recognizing Insider Threats

- changes in user behavior
- lifestyle incongruencies

### Password Management

- password manager. remembers usernames and passwords for all sites.

### Avoiding Social Engineering

- social engineering. attackers trick individuals into bypassing an orgs security procedures.
- situational awareness. mindful of surroundings and the potential consequences of one's actions.
- shoulder surfing. peek. attackers take a look.
- eavesdropping. attacker tries to listen in.
- piggybacking/tailgating.
- dumpster diving
- operational security (opsec)

### Policy and Handbooks

- policy. system of rules that guide decisions and actions.
- handbook. comprehensive guide w/ detailed information on procedures, guidelines, etc.

### Remote and Hybrid Work Environments

- remote work. work from location outside a traditional office.
- hybrid work. combination of traditional office settings with remote work options.

### Creating a Culture of Security

- organizational change management (OCM).

## Session 28: Conclusion

### Conclusion

- THE END.
- top 5 tips to increase scores.
- 1 use a cheat sheet.
- 2 skip the simulations. mark them for review and then go back and do the simulations at the end.
- 3 take a guess when in doubt of the right answer. eliminate options.
- 4 pock the best time for the exam.
- 5 be confident.
- take practice exams.
- buy additional practice exams from jason dion's site. diontraining.com/vouchers 

### BONUS: Where do I go from here?

- sales pitch for his other courses.

## Session 29: Practice Exam

- 
