:tocdepth: 1

.. sectnum::

.. note::

   **This technote is not yet published.**

   A threat model, survey of risk areas, catalog of known security gaps, and recommended mitigations for the Science Platform.

.. _abstract:

Abstract
========

The Science Platform is a collection of software and services that provides data rights holders and Vera C. Rubin Observatory team members access to the LSST data and support for its scientific analysis.
This access is provided via a range of cooperating interfaces (Python APIs, Web APIs, and a graphical user interface), and, in addition, provides computing and storage resources to users.
Users will be able to selectively share the data they have stored.
An estimated 7,500 users from a wide variety of institutions will have Science Platform access.

This tech note proposes a threat model for analyzing the security risks of the Science Platform, catalogs known gaps under that threat model, and recommends mitigations for those gaps.

.. _scope:

Scope
=====

This security risk assessment covers the Science Platform as defined by `LDM-542`_ and `LDM-554`_.
It discusses Vera C. Rubin Observatory infrastructure only insofar as it supports the Science Platform and does not analyze the security of other project facilities.
It also does not cover other installations of the Notebook Aspect of the Science Platform outside of the Science Platform itself, such as at the Summit facility or the various project-internal test facilities.
For a related discussion of internal services maintained by the Science Quality and Reliability Engineering team, see `SQR-037`_.

.. _LDM-542: https://ldm-542.lsst.io/
.. _LDM-554: https://ldm-554.lsst.io/
.. _SQR-037: https://sqr-037.lsst.io/

The authentication and authorization model for the Science Platform is still under development.
(See `SQR-039`_ for some current discussion.)
This risk assessment therefore only deals with authentication and authorization at a high level and in generic terms.
It will be revised to include a specific analysis of the authentication and authorization system as implemented once that implementation becomes more concrete.

.. _summary:

Summary
=======

Security efforts for the Science Platform should focus on closing known vulnerabilities and defending against attackers doing mass vulnerability scans or using off-the-shelf exploit toolkits.
Within that framework, the security gaps that pose the highest risk are:

- :ref:`Security patching and upgrades <gap-patching>`
- :ref:`Logging and alerting <gap-logging-alerting>`
- :ref:`Notebook attacks on services <gap-notebook-cluster>`

The top recommendations for improving the Science Platform's security posture are:

- Automate or regularly schedule patching and upgrades of critical services
- Define normal administrative activity and begin alerting on unexpected privileged actions
- Isolate notebook pods spawned by the Notebook Aspect so that they cannot make direct network connections to internal Science Platform services and have to use the ingress.

Given the wide institutional and geographic diversity of the projected user base and the accompanying lack of management of or visibility into user endpoints, the Science Platform should be designed to assume that some of its users will be compromised at any given time.
The goal of Science Platform security measures should therefore not be to prevent any compromise, but instead to limit the number of attack points, detect successful attackers, limit the scope and damage of their activities, and cut off their access when they have been detected.

This review is preliminary and is expected to expand as more information is gathered.

See :ref:`Accepted Risks <accepted-risks>` for discussion of apparent security risks that should not be a focus of time or resources.
See :ref:`Glossary <glossary>` for some possibly-unfamiliar security terms.

.. _threat-model:

Threat model
============

.. _threat-model-targets:

Targets
-------

The expected goals of an attacker targeting the Science Platform are primarily the standard goals for general Internet attackers:

- Theft of compute resources (Bitcoin mining, bot networks)
- Extortion via ransomware (CryptoLocker)
- Web site hosting for further phishing or malware distribution
- Exfiltration of confidential data such as password databases

Additionally, since Rubin Observatory is prominent (receives news media coverage) and is associated with the US government, some attackers may want to embarrass Rubin Observatory or claim credit for hacking a well-known site.
Those attackers are likely to attempt web site defacement or release of non-public data that would embarrass Rubin Observatory or its sponsors.

The observatory data accessible via the Science Platform, while not all public, is of limited financial or strategic value to sophisticated attackers.
While the Science Platform will hold some limited personal information for its users (primarily names, email addresses, and institutional affiliations), it will not contain stores of valuable personal data such as credit card numbers or :abbr:`SSNs (US Social Security Numbers)`), or valuable confidential data such as classified information or commercial trade secrets.
Unpublished astronomical research, while confidential, does not have the same appeal to attackers.
Therefore, targeted attacks by sophisticated attackers looking for data of monetary or political value are unlikely.

.. _threat-model-attackers:

Attacker profile
----------------

Rubin Observatory should expect attacks from, and defend against:

- Viruses, worms, and other automatically-spreading attacks
- Phishing via mass spam or unsophisticated spear-phishing
- Automated exploits based on mass scanning and opportunistic exploitation
- Targeted attacks by people with off-the-shelf exploit toolkits
- Attempts to leverage stolen user credentials into access to Science Platform infrastructure

The most likely attack pattern is mass scanning of all Internet-facing resources for known flaws, followed by automated or toolkit-based manual follow-up on discovered flaws.
The second most likely attack pattern is interactive exploration of public-facing web sites and resources looking for software and web security vulnerabilities with known exploits.
The third most likely attack pattern is compromise of the endpoint of an individual Science Platform user, and thus compromise of their access tokens and authentication credentials, followed by an attempt to use that access to abuse Science Platform resources or gain access to its infrastructure.

Rubin Observatory should therefore focus security efforts on patching known security vulnerabilities, avoiding obvious web security problems, detecting and cutting off abuse of stolen access credentials, limiting the damage that can be done by an individual user, and preventing escalation of access from an individual user account to Science Platform infrastructure.

Given the limited value to attackers of Science Platform resources nad data, Rubin Observatory should not attempt to defend the Science Platform against :abbr:`APTs (Advanced Persistent Threats)`, state actors, or sophisticated organized crime.
The focus of security efforts for the Science Platform should not be on attackers with the capability to develop or purchase unknown zero-day exploits, construct novel exploit toolkits, implant hardware into endpoints, or pursue careful and sophisticated targeted phishing attacks.
Defense against this level of attacker would not be a good use of project resources given the extremely high cost of defense and the relatively low likelihood of interest in Science Platform services by well-funded attackers.

Rubin Observatory should also not attempt to implement technical defenses against insider attacks.
Insider threats are the most difficult type of attack to defend against, and require the most intrusive and disruptive security controls.
Rubin Observatory should accept the technical security risk of a malicious employee and mitigate that risk through management, legal, and HR policies and awareness.

.. _threat-model-discussion:

Discussion
----------

Defending against security threats costs resources in the form of time, money, and staff.
As with any other aspect of a project, there is a budget for security, and exceeding that budget would undermine the success of other parts of the project.
Therefore, that budget should be spent wisely on the most effective security measures, not on defending against any conceivable security threat.

A security budget poses some special challenges because it is distributed.
Many security measures impose small and hard-to-quantify costs on large numbers of people, instead of a large but known cost on a single budget.
Security measures therefore need to be carefully chosen to avoid large hidden costs spread throughout the organization and death of other project goals by a thousand cuts.

A threat model is a tool to analyze how to spend a security budget.
It serves two primary purposes in a security risk assessment:

#. Focus security efforts on the most likely attackers and attack paths, where the work will achieve the most benefits for the cost.
#. Explicitly accept the risk of attacks and attackers for which defense is not a realistic goal.
   This avoids spending scarce security resources on problems that are not solvable within the project security budget.

The cost of defense is generally proportional to the sophistication of attack.
Defending against the most sophisticated attackers requires a dedicated security response team and resources beyond the budget of nearly all organizations.
Rubin Observatory needs to be realistic about both what sophistication of attacks is likely given the data and resources entrusted to the project and what defense is feasible given the available budget.
Attempting to defend against every possible attack is a waste of both project resources and project member good will.

If the project is attacked by a particularly sophisticated attacker, that attacker will probably be successful.
That is an acceptable risk for the project to take.

This threat model is based on the following assumptions about project security resources:

- Primary responsibility for security work will be distributed among everyone maintaining project services and needs to consume a small and bounded portion of their time.
- Dedicated security resources are limited.
  Some security-critical services may be run by dedicated security staff, but otherwise the role of a security team will be limited to standards, frameworks, consultation, and advice.
- The project does not have resources for a dedicated detection and response team.
  Detection and response will be done by general project staff in the course of normal service operations.
- The project does not have resources for a dedicated red team (offensive security testing), and at best limited resources for penetration testing.

This rules out effective defense against state actors, sophisticated organized crime, or insider threats.
Thankfully, as explained in :ref:`Threat Model: Targets <threat-model-targets>`, it is also unlikely that such attackers would spend resources attempting to compromise Science Platform services given the lack of (to them) interesting targets.

Finally, the Science Platform, by design, will be used by researchers all over the United States and potentially the world, using endpoints that will not be managed by Rubin Observatory.
Rubin Observatory therefore has limited ability to detect or prevent compromise of any authentication credentials visible to the user and their endpoints.
It is inevitable given the size and distributed nature of the user community that at least one Science Platform user will have their credentials compromised over the course of the project.
This risk assessment therefore assumes that some Science Platform users will be compromised and therefore some attackers will be able to attack the system from the position of an authenticated user.

.. _gaps:

Known gaps
==========

Summary
-------

.. _table-summary:

.. table:: Summary of gaps

   +------------------+------------------------------+--------+
   | Class            | Gap                          | Risk   |
   +==================+==============================+========+
   | Infrastructure   | :ref:`gap-patching`          | High   |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-logging-alerting`  | High   |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-notebook-cluster`  | High   |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-escalation`        | Medium |
   +------------------+------------------------------+--------+
   | Software         | :ref:`gap-input`             | Medium |
   +------------------+------------------------------+--------+
   | Web security     | :ref:`gap-csp`               | Medium |
   +------------------+------------------------------+--------+
   | Authentication   |                              |        |
   +------------------+------------------------------+--------+
   | Abuse            |                              |        |
   +------------------+------------------------------+--------+
   | Data security    | :ref:`gap-data-corruption`   | Low    |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-data-user`         | Low    |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-data-project`      | Low    |
   +------------------+------------------------------+--------+

.. _gaps-infra:

Infrastructure
--------------

.. _gap-patching:

Security patching
^^^^^^^^^^^^^^^^^

**Risk: High**

Due to the distributed user population, the Science Platform is Internet-accessible by design.
This means there is a substantial Internet-facing attack surface, which increases the risk of vulnerabilities in software used by the Science Platform.
This is also the most likely attack vector for both opportunistic mass scanning attacks and more targeted attacks attempting to deface project web sites or to embarrass the project.

The Science Platform is deployed on top of Kubernetes, which reduces the risk of local compromise of a service since the attacker will be confined to the container.
However, container escapes are not uncommon, which could allow lateral movement between pods on the same host, or between hosts within the Data Facility.
An attacker would also be able to intercept traffic, attack internal services and backend storage, and steal security credentials and sensitive data traveling through the compromised pod.

Therefore, all software that is part of a plausible attack path should be regularly patched for security vulnerabilities.
Attack path analysis to determine if a given security vulnerability in a software component affects the Science Platform is difficult, costly, and error-prone, and it is difficult to be certain that a given upgrade has no security implications.
Best practice is therefore to routinely upgrade all software dependencies to the latest stable release.

That said, this will not be possible for all Science Platform code.
There is a large amount of locally-developed code underlying components of the Science Platform, some of which includes complex, multi-layered dependencies that are difficult to upgrade.
For that software, the security risk has to be balanced against the stability and resource risk of constant upgrades, and other techniques should be used to mitigate the risk.
See :ref:`Input sanitization <gap-input>` and :ref:`Content security policy <gap-csp>`.

Regular patching is the most critical for compiled binaries in non-memory-safe languages that are part of the external attack surface such as NGINX or Python Docker images.
Many of those components can be patched independently of the complex Rubin-specific code, and should be.
Regular patching is less critical for underlying libraries in memory-safe languages, such as Python libraries.

Software upgrades are currently done opportunistically or as a side effect of other operational work, which means that stable services that don't need new features may be left unpatched for extended periods of time.
For instance, there currently isn't a process to be notified of a new NGINX security vulnerability and patch the Science Platform NGINX Kubernetes ingress.
Similarly, there should be a systematic process for patching the kernels of the hosts running the Science Platform Kubernetes pods.

Known, unpatched security vulnerabilities are the most common vector for successful compromises.

Mitigations
"""""""""""

- The Internet-facing attack surface always passes through an NGINX ingress that terminates both TLS and HTTP, which avoids TLS and HTTP protocol attacks except those against NGINX.
- Cloud providers are used for many vulnerability-prone services such as DNS, reducing the attack surface.
- Nearly all Science Platform components use memory-safe languages (Python, Go, JavaScript, Java) to interact with user-provided data and requests, avoiding many common remote vulnerabilities.

Recommendations
"""""""""""""""

- Automate upgrade and redeployment of NGINX ingress services on a regular schedule.
  Both web servers and TLS libraries are common sources of vulnerabilities.
- Automate or create a routine process for patching the operating system of Kuberntes nodes.
- Automate or create a routine process for applying pending Kubernetes controller and node upgrades.
- Automate or create a routine process for updating the base Docker image and other installed third-party software packages on which Science Platform services are built.
- Create a routine process or, preferably, automation to upgrade and redeploy Internet-facing services to pick up all security patches.
  This may not be possible for Science Platform services with complex dependencies, but there are many simpler components for which this is possible.
- Monitor and alert on failure to upgrade any of the above services or components within an acceptable window.
- Upgrade dependencies, rebuild, and redeploy all services, even those that are not Internet-facing, on a regular schedule to pick up security patches.
  This is less important than Internet-facing services, but will close vulnerabilities that are indirectly exploitable, and also spreads operational load of upgrades out over time.
  This schedule can be less aggressive than the one for Internet-facing services, and must be balanced against the stability requirements of Science Platform components.

.. _gap-logging-alerting:

Logging and alerting
^^^^^^^^^^^^^^^^^^^^

**Risk: High**

Logs of privileged actions and unusual events are vital for security incident response, root cause analysis, recovery after an incident, and alerting for suspicious events.
The Science Platform does have consolidated logging but does not have alerts on unexpected activity, and not all components log the necessary data to do activity analysis.

All application and infrastructure logs for the Science Platform should be consolidated into a single searchable log store.
The most vital logs to centralize and make available for alerting are administrative actions, such as manual Argo CD, Helm, and Kubernetes actions by cluster administrators, and security logs from the Data Facility.
The next most important target is application logs from security-sensitive applications, such as Vault audit logs and Argo CD logs.
Detecting compromised user credentials or abuse of Science Platform services requires activity logs from all Science Platform components.

The complexity of the NGINX ingress of a Kubernetes cluster can also interfere with getting the user IP address, which is important for correlating security events.
Currently, logs from the Science Platform authentication service show requests coming from the Kubernetes pod of the NGINX ingress rather than the user's client.

Recommendations
"""""""""""""""

- Ingest logs from all components.
- Review and improve the logging of Science Platform components with security in mind.
  Some components may need to add additional logging or log in a more structured form to allow for automatic correlation and analysis.
- Ingest security logs from the Data Facility into the same framework.
- Write alerts for unexpected administrative actions and other signs of compromise.
  One possible alerting strategy is to route unexpected events to a Slack bot that will query the person who supposedly took that action for confirmation that they indeed took that action, with two-factor authentication confirmation.
  If this is done only for discouraged paths for admin actions, such as direct Kubernetes commands instead of using Argo CD, it doubles as encouragement to use the standard configuration management system.

.. _gap-notebook-cluster:

Notebook attacks on services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: High**

The Science Platform includes a Notebook Aspect that gives the user access to a Jupyter Notebook running within the Science Platform Kubernetes cluster.
A Jupyter Notebook is remote code execution by design.
It is a Linux host on which the user can execute arbitrary code.
Since it is also located within the Kubernetes cluster, it can be used as a platform to explore services exposed only within the Kubernetes cluster and attempt to attack them.

The authentication model for services in the Science Platform applies authentication and authorization controls at the ingress.
However, connections from inside the Kubernetes cluster can bypass the ingress and access the underlying service directly.
This could allow an attacker to bypass authentication controls, claim to be any user, attack services that depend on authorization for their security, and otherwise move laterally through the Kubernetes cluster.

These concerns and recommendations also apply to any other part of the Science Platform that allows execution of arbitrary user-provided code, such as a batch processing cluster.

Mitigations
"""""""""""

- Access to the notebook is protected by authentication.
  An attacker therefore first has to compromise a Science Platform user and then use their credentials to access the notebook, or trick a Science Platform user into running attacker code.
  However, as noted in :ref:`the summary <summary>`, it is inevitable that a Science Platform user will be compromised at some point during the project and an attacker will be able to gain notebook access.
- Users may notice and notify Rubin Observatory staff of attacker use of their notebooks.

Recommendations
"""""""""""""""

- Isolate Notebook Aspect pods, and any other Science Platform services that provide arbitrary code execution, to their own network environment.
  Require that they talk to other Science Platform services via an ingress rather than direct connections to other cluster services.
- For those services that must be accessible from the notebook pods, such as other components of JupyterHub, ensure that those services require and check authentication credentials.
- Log and alert on unexpected patterns of access from notebooks, such as large numbers of failing requests or requests to routes that the Notebook Aspect would have no reason to access.
  Respond to those alerts by suspending or terminating pods and investigating for malicious activity.

Alternately, each Science Platform service could implement authentication and authorization directly, so that bypassing the ingress creates no meaningful change in the security of the service.
However, this requires adding security controls to each service independently, which is considerably more work and loses the consolidation benefits of using a single service for all authentication and most authorization decisions.

.. _gap-escalation:

Notebook privilege escalation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Medium**

Similar to :ref:`notebook attacks on services <gap-notebook-cluster>`, an attacker can use arbitrary code execution within the notebook to gain elevated permissions inside the notebook pod or the host running the Kubernetes pod.
From there, an attacker may be able to attack internal services or move laterally through the cluster.

Kubernetes attempts to allow untrusted workloads to run inside a pod, but is not strongly hardened against them.
It does not use user namespaces and exposes most of the attack surface of the Linux kernel to code running inside a pod.

Similarly, an attacker may be able to use the Notebook Aspect attack internal Kubernetes APIs and escalate privileges that way.
See, for example, `CVE-2018-1002105`_.

.. _CVE-2018-1002105: https://blog.aquasec.com/kubernetes-security-cve-2018-1002105

Protections against this attack are complicated by the need to launch Notebook Aspect pods under specific UIDs and GIDs to support UID-based access control to underlying NFS storage.
This in turn requires the pod launching process to be privileged and able to switch to arbitrary UNIX users, which increases the risk of privilege escalation.

Mitigations
"""""""""""

- Access to the notebook is protected by authentication.
  An attacker therefore first has to compromise a Science Platform user and then use their credentials to access the notebook, or trick a Science Platform user into running attacker code.
  However, as noted in :ref:`the summary <summary>`, it is inevitable that a Science Platform user will be compromised at some point during the project and an attacker will be able to gain notebook access.
- Users may notice and notify Rubin Observatory staff of attacker use of their notebooks.

Recommendations
"""""""""""""""

The primary defense is the same as recommeded for :ref:`security patching <gap-patching>`, namely:

- Automate or create a routine process for patching the operating system of Kuberntes nodes.
- Automate or create a routine process for applying pending Kubernetes controller and node upgrades.

In addition:

- Ensure Notebook Aspect pods are run with as restrictive of a pod security policy as possible given the required use of those pods.
- Minimize Kubernetes service account permissions granted to Notebook Aspect pods.
- Isolate user Notebook Aspect pods on their own hosts that are not shared with other Science Platform services.
  Ideally this should be combined with the network restrictions discussed under :ref:`notebook attacks on services <gap-notebook-cluster>`.
  Then, if an attacker manages to escalate permissions from a Notebook Aspect pod, they would still be in a restricted environment that would limit lateral movement to other Notebook Aspect pods that would be under similar restrictions.
- Collect system logs from Notebook Aspect pod hosts and alert on unexpected errors that may be a sign of attempted privilege escalation.
- Collect Kubernetes API logs and alert on unexpected access patterns that may be a sign of attempted privilege escalation.

.. _gaps-software:

Software
--------

.. _gap-input:

Input sanitization
^^^^^^^^^^^^^^^^^^

**Risk: Medium**

The Science Platform is expected to have various API services accessible to users both via the Notebook and Portal Aspects and via direct API calls over the Internet.
Some of those services will accept user-provided data and run queries on behalf of the user.
They are therefore potentially vulnerable to buffer overflow attacks, SQL injection attacks, and other attacks common to Internet-accessible services.

Many of these services will be written by Rubin Observatory staff or affiliates.
Rubin Observatory will therefore be responsible for their security properties, rather than being able to lean on an external development community.

This same security concern applies to the Portal Aspect, which has a substantial UI component that takes user input.
It does not apply to the notebook execution portions Notebook Aspect, where arbitrary code execution is part of the expected use of the service.
It does apply to the parts of the infrastructure used to launch notebooks that are developed internally.

This gap focuses on software vulnerabilities in code written by Rubin Observatory.
For a discussion of security concerns with third-party software, see :ref:`security patching <gap-patching>`.

Mitigations
"""""""""""

- Most Science Platform service code, particularly the user-facing components, is written in memory-safe languages such as Python, which greatly reduces the risk of many types of security vulnerabilities.
  However, Science Platform services include components and underlying libraries written in memory-unsafe languages such as C++, and user input may be passed through to those libraries and components.
- All Science Platform services are expected to require authentication.
  An attacker therefore first has to obtain API credentials from a Science Platform user before being able to start an attack.
- The Science Platform is not an attractive target for sophisticated attackers that have the resources to analyze project code for flaws or attempt complex attacks.
  Attacks on API services will likely be limited to those that can be launched by off-the-shelf tools and superficial exploration.

Recommendations
"""""""""""""""

This is a difficult risk to mitigate because Science Platform code will largely be written by scientists attempting to solve problems in astronomy, not by software developers focusing on security concerns.
This is as it should be.
The purpose of the project is not to write secure APIs, but to advance research in astronomy.
However, SQL injection, poor handling of untrusted data, and other API vulnerabilities are a common avenue of attack, and many parts of those attacks can be automated with tools and run en masse by scanners.

The recommended balance to strike here is to invest moderately in libraries to assist with secure development practices, keep the exposed API attack surface area narrow when possible, and rely on peer code review rather than security review where possible.

- Use standard libraries for SQL queries and similar database actions, and use their default protections against SQL injection.
  Modern SQL libraries all have built-in, on-by-default protection against common SQL injection errors.
- Sanitize all input data from users as early as possible.
  Before calling into any underlying library, any user input should be checked for validity.
  As much as possible, implement those validity checks in standard code libraries that can be reused.
- Data sanitization should be verified with unit tests that attempt to send a variety of invalid data.
- All user-facing API code should be reviewed by at least one engineer other than the author, with a eye specifically to potential security vulnerabilities.
- Where resources permit, the user-facing API surface and input validation of the most prominant Science Platform services should get a thorough code review by someone with experience in secure coding practices.
  However, this type of review can be time-consuming, and it's not realistic to ask the project to block on this review.

.. _gaps-web-security:

Web security
------------

.. _gap-csp:

Content Security Policy
^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Medium**

The Notebook and Portal aspects are, by design, Internet-accessible to all users of the Science Platform.
The Science Platform also includes internal-facing web services with administrative access, such as `Argo CD`_ dashboards.
These services are attractive targets for XSS and other web attacks.
The primary defense is upstream security and keeping these applications patched, but a web `Content Security Policy (CSP)`_ would provide valuable defense in depth.

.. _Argo CD: https://argoproj.github.io/argo-cd/
.. _Content Security Policy (CSP): https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

A CSP is particularly of interest for the Notebook Aspect, since a successful XSS attack on it would lead directly to code execution within the user's notebook.

Currently, none of the Science Platform aspects or administrative interfaces have a CSP.
The most valuable restrictions would be ``script-src`` and ``style-src``.

Mitigations
"""""""""""

- Keeping the applications patched is the best first line of defense.

Recommendations
"""""""""""""""

- Add ``Content-Security-Policy`` headers to the most important applications.
  There are three possible approaches, each of which may be useful in different places.
  For third-party components deployed in the Science Platform such as Argo CD, ideally upstream should support CSP and present a complete CSP, and Rubin Observatory could potentially assist via upstream pull requests.
  For internally-developed components, Rubin Observatory should modify those applications to send a CSP.
  Alternately, NGINX could add a CSP at the Kubernetes ingress.

.. _gaps-data:

Data security
-------------

.. _gap-data-corruption:

Data corruption
^^^^^^^^^^^^^^^

**Risk: Low**

The most common attack on file system data today is ransomware.
CryptoLocker is the best-known example.
This is a type of malware that encrypts all data to which it has access, while replicating through a network, and then extorts money from the victim in exchange for the decryption key.
Attacks of this kind have become common and can be highly expensive and destructive.

One possible service that may be provided by the Science Platform is a mechanism for users to mount a file system from the Science Platform on their local computer for ease of program and data sharing.
This type of Science Platform access would then make any files accessible by that user vulnerable to a malware infection on the user's endpoint.

Mitigations
"""""""""""

- Malware of this type normally targets desktop or laptop computers running commodity operating systems (Windows or, more rarely, macOS) and normally spreads via network file shares that are common in corporate environments.
  The Science Platform runs on Linux and, with the exception of the file share service described above, does not use the type of network file share that this type of malware commonly targets.
- Most Science Platform project data will be provided read-only to individual users.
  This attack primarily affects data that is writable by a user, and thus is generally restricted to User Generated data.
- Science Platform file systems are backed up.

Recommendations
"""""""""""""""

The most effective defense against ransomware attacks (apart from prevention, which is mostly not under Rubin Observatory control if the attack originates from the local system of a user or from code downloaded and run by the user on their notebook) is backups.

- All user-writable directories should be backed up on a regular interval and kept for longer than the expected detection time of malware-corrupted files.
  The backups must not be user-writable so that the malware cannot also corrupt the backups.

.. _gap-data-user:

User metadata theft
^^^^^^^^^^^^^^^^^^^

**Risk: Low**

The Science Platform will store some data about each user of the platform.
This will include name, email address, linked federated identities, group membership, information provided in support of quota requests such as proposed scientific work, and access log information including IP addresses.
Rubin Observatory has an obligation to take reasonable steps to keep this personal data private.

Migitations
"""""""""""

- No high-value user data  such as credit card or bank account information or government identity information will be stored by the Science Platform.
- Since the Science Platform will rely entirely on federated authentication, no passwords will be stored.
- This data has little value from an attacker's perspective.
  It cannot be easily sold or used to obtain other high-value target information, such as classified information or commercial trade secrets.
  The risk of attacks by sophisticated attackers is therefore low, since this type of information is not worth their time and effort.

Recommendations
"""""""""""""""

- Limit access to log data, user databases, and other user metadata stores to authorized administrators using two-factor authentication.
- Restrict API access to user metadata to the Kubernetes cluster hosting the Science Platform.
  Do not provide Internet access to this data except via a web UI with good web security controls.

.. _gap-data-project:

Data theft after user compromise
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Low**

Given an expected distributed user population of 7,500 and the lack of strong security controls on endpoints, it is highly likely that at least one user will have their authentication credentials compromised.
An attacker could then use those credentials to download from the Science Platform non-public data to which the compromised user had access.
This type of compromise will be difficult to detect, since download of data will be part of the normal, expected use of the platform.

An attacker is highly unlikely to be able to or want to download and republish sufficient non-public Data Release data to have a meaningful impact on Rubin Observatory goals.
User Generated data is more confidential and may be less voluminous and thus more vulnerable to attack.

That said, it's also not within the reasonable capabilities of the Science Platform to keep confidential User Generated data when the authentication credentials or endpoint of the user who generated or was given access to that data have been compromised outside of the Science Platform.
Primary responsibility for endpoint security and secure storage of access tokens lies with the user.

See `LPM-231`_ for more details about the types of data stored in the Science Platform.

.. _LPM-231: https://lpm-231.lsst.io/

Mitigations
"""""""""""

- The monetary value of non-public LSST data is low.
  This means low motivation for an attacker to download that data.
- User Generated data is of potential interest primarily within the field of astronomy and is unlikely to be a meaningful target for a typical attacker.

Recommendations
"""""""""""""""

- Require authentication and secure protocols for access to data stores.
- Lock accounts if it becomes apparent that they have been compromised.
- Provide guidance to users on secure storage of access credentials.

.. _accepted-risks:

Accepted risks
==============

The following possible security gaps do not appear to be significant enough to warrant investment of Rubin Observatory resources given the threat model, or are inherent in the nature of the Science Platform and cannot be avoided.

User endpoint security
----------------------

If Rubin Observatory had the resources and ability to ensure a baseline level of security on the endpoints that users of the Science Platform use to access the service, it could significantly improve the security of the service.
However, this is not possible by design.
The purpose of the Science Platform is to provide an interactive data exploration and analysis environment to widely distributed researchers with no direct affiliation with Rubin Observatory.
Therefore, the risk of compromise that comes with a lack of endpoint security measures is a risk the project is forced to accept.

The implication is that it is likely that user endpoints will be compromised over the lifetime of the project, and thus attackers will gain access to user credentials and be able to access the Science Platform pretending to be a legitimate user.
This implies that the Science Platform security controls have to be at least somewhat robust against attacks from users with authenticated access to the platform.

.. _glossary:

Glossary
========

APT
    An advanced persistent threat.
    An attack aimed at achieving persistence (repeatable access to an environment) in order to steal high-value data.
    These attacks are narrowly targeted at a specific site and often involve significant research and analysis of the security practices of the target.
    They prioritize avoiding detection, in contrast to the more typical "smash and grab" attacks of less sophisticated attackers.
    An APT is a sign of well-funded attackers, either large-scale organized crime or **state actors**.

endpoint
    The device with a screen and keyboard into which one is directly typing.
    A collective term for work laptops, desktops, personal laptops and desktops, mobile devices, and any other end-user device with screen and keyboard used in the course of project work.
    An attacker with full access to an endpoint has full access to anything accessed from that endpoint, can steal authentication credentials, and can impersonate the user of that device or piggyback on their authenticated connections.
    Security of endpoints is therefore critical to the security of any overall system.

insider threat
    An attack by a trusted member of the organization being attacked.
    For example, a service maintainer using their privileged access to that service to steal data for non-work purposes.

penetration testing
    Testing services and systems for vulnerabilities that could be exploited by an attacker.
    Penetration testing comes in a wide range of levels of sophistication and effectiveness, ranging from running an off-the-shelf security scanner like Nessus to hiring a professional **red team**.
    The less-sophisticated forms of penetration testing are prone to huge numbers of false positives.

phishing
    An attempt to trick someone into revealing their security credentials or other information of value to an attacker.
    Most commonly done via email.
    A typical example is an email purporting to be from one's bank or credit card company, asking the recipient to verify their identity by providing their account credentials to a web site under the attacker's control.
    Most phishing attacks have telltale signs of forgery (misspelled words, broken images, questionable URLs, and so forth), and are sent via untargeted mass spam campaigns.
    See **spear-phishing** for the more sophisticated variation.

ransomware
    Malware that performs some reversible damage to a computer system (normally, encrypting all files with a key known only to the attacker), and then demands payment (usually in Bitcoin) in return for reversing the damage.
    CryptoLocker is the most well-known example.

red team
    A security team whose job is to simulate the actions of an attacker and attempt to compromise the systems and services of their employer or client.
    The intrusion detection and response team responsible for detecting the attack and mitigating it is often called the "blue team."
    The terminology comes from military training exercises.

security control
    Some prevention or detection measure against a security threat.
    Password authentication, second-factor authentication, alerts on unexpected administrative actions, mandatory approval steps, and automated security validation tests are all examples of security controls.

spear-phishing
    A targeted phishing attack that is customized for the recipient.
    A typical example is a message sent to a staff member in HR and forged to appear to be from a senior manager, asking for copies of employee W-2 forms or other confidential information.
    Spear-phishing from professional attackers can be quite sophisticated and nearly indistinguishable from legitimate email.

state actor
    Professional attackers who work for a government.
    The most sophisticated tier of attackers, with capabilities beyond the defensive capacity of most organizations.
    Examples include the US's :abbr:`NSA (National Security Agency)` and China's Ministry of State Security.
    See **APT**.

XSS
    Cross-site scripting.
    One of the most common web vulnerabilities and attacks.
    Takes advantage of inadequate escaping or other security flaws in a web application to trick a user's web browser into running JavaScript or other code supplied by the attacker in the user's security context.
    Can be used to steal authentication credentials such as cookies, steal other confidential data, or phish the user.
