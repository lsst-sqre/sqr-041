:tocdepth: 1

.. _abstract:

Abstract
========

The Rubin Science Platform (RSP) is a collection of software and services that provides data rights holders and Vera C. Rubin Observatory team members access to the LSST data and support for its scientific analysis.
This access is provided via a range of cooperating interfaces (Python APIs, web APIs, and a graphical user interface), and, in addition, provides computing and storage resources to users.
Users will be able to selectively share the data they have stored.
An estimated 10,000 users from a wide variety of institutions will have Science Platform access.

This tech note proposes a threat model for analyzing the security risks of the Science Platform, catalogs known gaps under that threat model, and recommends mitigations for those gaps.

The configuration discussed in this tech note is implemented by Phalanx_, the Kubernetes configuration for the Rubin Science Platform.

.. _Phalanx: https://phalanx.lsst.io/

.. _scope:

Scope
=====

This security risk assessment covers the Science Platform as defined by LDM-542_ and LDM-554_.
It discusses Vera C. Rubin Observatory infrastructure only insofar as it supports the Science Platform and does not analyze the security of other project facilities.
It also does not cover other installations of the Notebook Aspect of the Science Platform outside of the Science Platform itself, such as at the Summit facility or the various project-internal test facilities.
For a related discussion of internal services maintained by the Science Quality and Reliability Engineering team, see SQR-037_.

.. _LDM-542: https://ldm-542.lsst.io/
.. _LDM-554: https://ldm-554.lsst.io/
.. _SQR-037: https://sqr-037.lsst.io/

This risk assessment only covers risks associated with the data that will be released for general users of the Science Platform.
It does not discuss security risks of data and processing prior to or not included in that data release, such as prompt processing, unreleased raw images, security of the telescope itself and its related support equipment, or transfer of data to repositories used by the Science Pipeline.

The authentication and authorization model for the Science Platform is discussed in detail in DMTN-234_, DMTN-224_, and SQR-069_.
Those details will not be repeated here; instead, only known issues and limitations that affect the overall security of the platform will be noted.
For a much deeper analysis of authentication and authorization, see those documents.

.. _DMTN-234: https://dmtn-234.lsst.io/
.. _DMTN-224: https://dmtn-224.lsst.io/
.. _SQR-069: https://sqr-069.lsst.io/

.. _summary:

Summary
=======

Security efforts for the Science Platform should focus on closing known vulnerabilities and defending against attackers doing mass vulnerability scans or using off-the-shelf exploit toolkits.
Within that framework, the security gaps that pose the highest risk are:

- :ref:`Dask access for notebooks <gap-dask>`
- :ref:`Logging and alerting <gap-logging-alerting>`
- :ref:`CSRF and credential leakage <gap-csrf>`

The top recommendations for improving the Science Platform's security posture are:

- Replace the direct Kubernetes access currently granted to the Notebook Aspect to support Dask with a separate authenticated service as described in SQR-066_.
- Implement CSRF, XSS, and credential leakage protection as discussed in DMTN-193_.
- Review and improve the logging of Science Platform components with security in mind.
- Write alerts for unexpected administrative actions and other signs of compromise.

.. _SQR-066: https://sqr-066.lsst.io/
.. _DMTN-193: https://dmtn-193.lsst.io/

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

- Extortion via ransomware (CryptoLocker)
- Theft of compute resources (cryptocurrency mining, bot networks)
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

Given the limited value to attackers of Science Platform resources and data, Rubin Observatory should not attempt to defend the Science Platform against :abbr:`APTs (Advanced Persistent Threats)`, state actors, or sophisticated organized crime.
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

This is not a comprehensive look at every security control.
(That would be a much longer document, and difficult to keep up to date.)
Rather, this focuses on the areas most likely to cause problems or most likely to arise in a security review.
That may be because it's an area of active threat or attacker interest, or an area where the current security controls are weak.

Risks are categorized as high, medium, and low to aid in prioritization.
Rubin Observatory has limited security resources and cannot address all recommendations here simultaneously.
The areas marked as highest risk are the areas where the security improvements will have the largest payoff in overall Science Platform security.

Summary
-------

.. _table-summary:

.. table:: Summary of gaps

   +------------------+------------------------------+--------+
   | Class            | Gap                          | Risk   |
   +==================+==============================+========+
   | Infrastructure   | :ref:`gap-logging-alerting`  | High   |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-kubernetes`        | Medium |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-patching`          | Medium |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-admin-compromise`  | Medium |
   +------------------+------------------------------+--------+
   | Notebooks        | :ref:`gap-dask`              | High   |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-notebook-cluster`  | Medium |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-escalation`        | Low    |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-notebook-secrets`  | Low    |
   +------------------+------------------------------+--------+
   | Software         | :ref:`gap-input`             | Medium |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-data-handling`     | Low    |
   +------------------+------------------------------+--------+
   | Web security     | :ref:`gap-csrf`              | High   |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-csp`               | Medium |
   +------------------+------------------------------+--------+
   | Authentication   | :ref:`gap-api-credentials`   | Medium |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-idp-compromise`    | Low    |
   +------------------+------------------------------+--------+
   | Abuse            | :ref:`gap-abuse-content`     | Low    |
   |                  +------------------------------+--------+
   |                  | :ref:`gap-abuse-compute`     | Low    |
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

.. _gap-logging-alerting:

Logging and alerting
^^^^^^^^^^^^^^^^^^^^

**Risk: High**

Logs of privileged actions and unusual events are vital for security incident response, root cause analysis, recovery after an incident, and alerting for suspicious events.
The Science Platform does have consolidated logging at the Interim Data Facility via Google Log Explorer, but does not have alerts on unexpected activity, and not all components log the necessary data to do activity analysis.

All application and infrastructure logs for the Science Platform should be consolidated into a single searchable log store.
The most vital logs to centralize and make available for alerting are administrative actions, such as manual Argo CD, Helm, and Kubernetes actions by cluster administrators, and security logs from the Data Facility.
The next most important target is application logs from security-sensitive applications, such as Vault audit logs and Argo CD logs.
Detecting compromised user credentials or abuse of Science Platform services requires activity logs from all Science Platform components.

The complexity of the NGINX ingress of a Kubernetes cluster can also interfere with getting the user IP address, which is important for correlating security events.
Some Science Platform applications (mostly those written in-house by Rubin Observatory) use header information injected by the NGINX ingress to log the true client IP address.
Others, particularly third-party applications, show requests coming from the Kubernetes pod of the NGINX ingress instead.

Recommendations
"""""""""""""""

- Ensure consolidated logging is maintained in the transition from the Interim Data Facility to the final US Data Facility.
- Review and improve the logging of Science Platform components with security in mind.
  Some components may need to add additional logging or log in a more structured form to allow for automatic correlation and analysis.
  Some components, particularly third-party components, may need configuration or filtering to locate the most interesting messages.
- Ingest security logs from the Data Facility into the same framework.
- Write alerts for unexpected administrative actions and other signs of compromise.
  One possible alerting strategy is to route unexpected events to a Slack bot that will query the person who supposedly took that action for confirmation that they indeed took that action, with two-factor authentication confirmation.
  If this is done only for discouraged paths for admin actions, such as direct Kubernetes commands instead of using Argo CD, it doubles as encouragement to use the standard configuration management system.

.. _gap-kubernetes:

Kubernetes hardening
^^^^^^^^^^^^^^^^^^^^

**Risk: Medium**

Default Kubernetes security settings for both clusters and pods are optimized for quick usability rather than security.
The shared platform and arbitrary code execution nature of the Science Platform Notebook Aspect calls for additional hardening beyond the Kubernetes defaults.
In addition, the Science Platform will comprise multiple services, some of which will be pinned to specific versions of a software stack for science reasons or which are provided by third parties, and thus may not be possible to regularly patch for security vulnerabilities.
(See :ref:`Security patching <gap-patching>`.)
This increases the chances that an attacker may be able to compromise a service pod, and thus the need to harden the Kubernetes infrastructure itself against a compromised pod.

Kubernetes pods run within Linux namespaces and thus may make use of Linux hardening and access control features.
Many security settings will hamper an attacker even if they are able to escape some namespaces.

Cloud Kubernetes environments, such as that used by the Interim Data Facility, have their own hardening options and configuration which can be enabled to limit the damage an attacker can do after compromising a pod.

Mitigations
"""""""""""

- ``automountServiceAccountToken`` is set to ``false`` for all pods except those that have a specific need to talk to the Kubernetes API.
- Most pods have security hardening applied.
- Most services define a ``NetworkPolicy``.
- The Interim Data Facility and expected Cloud Data Facility will be hosted in a cloud Kubernetes environment, and thus will benefit from the hardening that the cloud provider does by default.
- Each application in the Science Platform is isolated in its own namespace.

Recommendations
"""""""""""""""

Implement the remainder of the hardening recommendations documented in SQR-048_.
Specifically, for all Kubernetes environments:

.. _SQR-048: https://sqr-048.lsst.io/

- Implement a cluster-wide default restricted `Pod Security Standard`_ policy enforced with an admission controller.
  This will force use of pod hardening best practices except for those services that require special exceptions because they need to run privileged containers.
- Ensure all pods other than special privileged containers are configured to run as a non-root user with privilege escalation and capabilities disabled and a read-only root file system.
- Define ``NetworkPolicy`` resources for all pods that restrict at least the ingress.
  (Egress restrictions would be ideal but may be too difficult to maintain.)
- Specify resource limits for all pods.
- Use the GKE Sandbox for services where possible.
- Scan Kubernetes environments for all objects not managed by Argo CD and alert on anything unexpected.
- Review ``get``, ``list``, and ``watch`` access to secrets and remove it where possible.

The following Phalanx_ applications currently do not follow the pod hardening recommendations:

- portal
- postgres (internal PostgreSQL server)
- tap
- tap-schema

Third-party Helm charts have also not been thoroughly reviewed.

The following Phalanx_ applications do not yet have a ``NetworkPolicy`` defined and should, or if they do have a ``NetworkPolicy``, it is not sufficiently restrictive:

- noteburst
- nublado2 (JupyterHub for the Notebook Aspect)
- plot-navigator
- postgres (internal PostgreSQL server)
- tap-schema

.. _Pod Security Standard: https://kubernetes.io/docs/concepts/security/pod-security-standards/

For the Interim Data Facility hosted on :abbr:`GKE (Google Kubernetes Engine)`, the following additional recommendations have not yet been implemented:

- Restrict cluster discovery permissions to only service accounts plus the Google Cloud Identity organization instead of the default of ``system:authenticated``.
  (This will be unnecessary if the cluster is made private, as described in the next bullet point.)
- Restrict network access to the control plane and nodes.
  This is challenging because the recommended way to do this is to use a VPN to link the Kubernetes network with a corporate network, which poses various challenges.
  However, exposing the cluster to the Internet is a significant increase in attack surface and therefore risk.
  The easiest approach may be a bastion hosted in :abbr:`GCE (Google Compute Engine)`.

See SQR-048_ for more details on the Kubernetes hardening recommendations.

Also see :ref:`Notebook attacks on services <gap-notebook-cluster>` and :ref:`Notebook privilege escalation <gap-escalation>`.

.. _gap-patching:

Security patching
^^^^^^^^^^^^^^^^^

**Risk: Medium**

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

Regular patching is the most critical for compiled binaries in non-memory-safe languages that are part of the external attack surface, such as NGINX or Python Docker images used by supporting Internet-accessible services.
Many of those components can be patched independently of the complex Rubin-specific code, and should be.
Regular patching is less critical for underlying libraries in memory-safe languages, such as pure Python libraries.

Software updates for external components managed by Rubin Observatory are handled via automated pull requests.
Upgrades for components of the Science Platform, however, are currently done opportunistically or as a side effect of other operational work, which means that stable services that don't need new features may be left unpatched for extended periods of time.

Known, unpatched security vulnerabilities are the most common vector for successful compromises.

Mitigations
"""""""""""

- The combination of GitHub Dependabot, WhiteSource Renovate, and `neophile <https://neophile.lsst.io/>`__ create automated PRs for updates to Python dependencies and external Helm charts.
  See `SQR-042`_ for more details.
  These pull requests are generally merged and deployed weekly.
- The Interim Data Facility is hosted on Google Kubernetes Engine with release channels and maintenance windows enabled, so the underlying Kubernetes control plane and nodes are regularly and automatically patched by Google.
- The Internet-facing attack surface always passes through an NGINX ingress that terminates both TLS and HTTP, which avoids TLS and HTTP protocol attacks except those against NGINX.
- Cloud providers are used for many vulnerability-prone services such as DNS, reducing the attack surface.
- Nearly all Science Platform components use memory-safe languages (Python, Go, JavaScript, Java) to interact with user-provided data and requests, avoiding many common remote vulnerabilities.

.. _SQR-042: https://sqr-042.lsst.io/

Recommendations
"""""""""""""""

- Ensure that the regular automated upgrades of the Kubernetes control plane and nodes is maintained in the transition from the Interim Data Facility to the final US Data Facility.
- Create a routine process or, preferably, automation to upgrade and redeploy Internet-facing services to pick up all security patches.
  This may not be possible for Science Platform services with complex dependencies, but there are many simpler components for which this is possible.
- Monitor and alert on failure to upgrade any of the above services or components within an acceptable window.
- Upgrade dependencies, rebuild, and redeploy all services, even those that are not Internet-facing, on a regular schedule to pick up security patches.
  This is less important than Internet-facing services, but will close vulnerabilities that are indirectly exploitable, and also spreads operational load of upgrades out over time.
  This schedule can be less aggressive than the one for Internet-facing services, and must be balanced against the stability requirements of Science Platform components.

.. _gap-admin-compromise:

Admin account compromise
^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Medium**

Science Platform and Data Facility administrators will need to have administrative access to the Kubernetes cluster and all components of the Science Platform.
An attacker who can steal their authentication credentials would get immediate, full access to the Science Platform to do whatever they wished.
Possible routes include:

- Theft of Kubernetes administrative credentials.
- Theft of credentials to any administrative UIs (such as the web dashboards for cloud services used as part of the Science Platform).
- Theft of credentials to directly obtain privileged access to Kubernetes nodes, which in turn would provide access to any secrets or credentials stored on those nodes.

The likely avenues of compromise are compromise of an endpoint used by an administrator followed by theft of stored credentials on that endpoint, or phishing of administrator credentials.

We also use Terraform via GitHub Actions to apply changes to the Google Cloud Platform projects and configuration that host the Interim Data Facility.
Currently, this is done via administrative credentials for the GCP environments stored as GitHub Actions secrets.

This risk as applied to Science Quality and Reliability Engineering staff is discussed in much greater detail in `SQR-037`_.

Mitigations
"""""""""""

- Two-factor authentication with a separate, dedicated account is required for Google Console access and Kubernetes access to the Interim Data Facility, although is not required to use the Kubernetes credentials once they have been obtained.
- Science Platform administrators are a small team of relatively sophisticated users who are less likely than most to click on phishing or install risky programs and more likely than most to notice strange system behavior after a compromise.
- Most malware is automated and unlikely to exploit saved credentials.
  It is more likely to be ransomware, adware, or to join the compromised system to an unsophisticated botnet to spread more malware.
  This would often allow detection and remediation before project services are compromised.

Recommendations
"""""""""""""""

Rubin Observatory does not have the resources available to do central device management well, and therefore should not attempt device management at all.
Instead, Rubin Observatory should focus on recommending caution in how staff use their work computers, and on reducing the impact of a compromise.

- Require two-factor authentication in some form before granting administrative access to the Science Platform.
  This could take several forms: Require a VPN or bastion host with mandatory two-factor authentication to perform Kubernetes administrative actions, force reauthentication with two factors before taking administrative actions, and mandatory two-factor authentication for external authentication providers such as GitHub or Google that are used to protect administrative access to the Science Platform.
- Avoid using work computers for testing unknown applications or visiting suspicious web sites, instead using mobile devices (preferred) or non-work devices without access to work credentials.
- Be vigilant about phishing, particularly when using a work computer.
- Prefer Git- and Slack-based work flows to direct access to services.
- Put expiration times on locally cached credentials where possible and where it is relatively easy to acquire new credentials so that stolen credentials cannot be used indefinitely into the future.
- Restrict two-factor authentication to stronger methods (OTP app, push, hardware token) rather than weaker methods (SMS, telephone call).

See `SQR-037`_ for more in-depth discussion.

To reduce the risk of compromise of credentials stored in GitHub Actions, switch to `GitHub OpenID Connect authentication <https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-google-cloud-platform>`__ to authenticate Terraform.

.. _gaps-notebook:

.. _gap-dask:

Dask access for notebooks
^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: High**

Some uses of the Science Platform may involve running compute-intensive tasks that may benefit from being distributed across multiple CPUs.
In its current implementation, this is provided via the Dask_ library and its Kubernetes support.
In order to enable this feature, user notebook pods are granted the ability to launch and manage new pods in the user's namespace.

.. _Dask: https://dask.org/

This currently grants Science Platform users the ability to run arbitrary pods with arbitrary privileges, including privileged pods.
That in turn could be used to undermine the security of the cluster, since Kubernetes is not hardened against privileged pods.

Also, in order to create the per-user service accounts required to support Dask, JupyterHub has Kuberentes access to create ``RoleBindings``.
That in turn may allow a compromised JupyterHub service to create a service account bound to a privileged role and from there compromise the cluster.

Recommendations
"""""""""""""""

Replace the current Dask approach, and the entire Notebook Aspect lab creation approach, with a lab Kubernetes controller as described in SQR-066_.
This isolates the privileged Kubernetes access in a separate service and would allow removing all Kubernetes API permissions from user lab pods.

As an additional benefit, this will allow removing all Kubernetes APi permissions from JupyterHub, replacing its direct use of Kubernetes APIs with web service calls to the lab controller.
While the extensive permissions JupyterHub currently must have are not a serious security concern (an attacker would still have to find a way to compromise JupyterHub first), JupyterHub is a highly complex and user-facing software package.
Moving permissions from it to a more limited-purpose, hardened web service would provide additional defense in depth.

.. _gap-notebook-cluster:

Notebook attacks on services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Medium**

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

- The impact of being able to bypass authentication once one already has aspect to a notebook is limited.
  Most Science Platform services are likely to allow access to all authenticated users.
  An attacker would be able to bypass quotas, but this is not a high-value target for most attackers.
  The primary concern is therefore access to administrative interfaces and bypass of ACLs on User-Generated Data.
- Access to the notebook is protected by authentication.
  An attacker therefore first has to compromise a Science Platform user and then use their credentials to access the notebook, or trick a Science Platform user into running attacker code.
  However, as noted in :ref:`the summary <summary>`, it is inevitable that a Science Platform user will be compromised at some point during the project and an attacker will be able to gain notebook access.
- Users may notice and notify Rubin Observatory staff of attacker use of their notebooks.

Recommendations
"""""""""""""""

- Isolate the Notebook Aspect pods, and any other Science Platform services that provide arbitrary code execution, using a network policy.
  Require that they talk to other Science Platform services via an ingress rather than direct connections to other cluster services.
- For those services that must be directly accessible from the notebook pods, such as other components of JupyterHub, ensure that those services require and check authentication credentials.
- Log and alert on unexpected patterns of access from notebooks, such as large numbers of failing requests or requests to routes that the Notebook Aspect would have no reason to access.
  Respond to those alerts by suspending or terminating pods and investigating for malicious activity.

.. _gap-escalation:

Notebook privilege escalation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Low**

Similar to :ref:`notebook attacks on services <gap-notebook-cluster>`, an attacker can use arbitrary code execution within the notebook to gain elevated permissions inside the notebook pod or the host running the Kubernetes pod.
From there, an attacker may be able to attack internal services or move laterally through the cluster.

Kubernetes attempts to allow untrusted workloads to run inside a pod, but is not strongly hardened against them.
It does not use user namespaces and exposes most of the attack surface of the Linux kernel to code running inside a pod.

Similarly, an attacker may be able to use the Notebook Aspect attack internal Kubernetes APIs and escalate privileges that way.
See, for example, CVE-2018-1002105_.

.. _CVE-2018-1002105: https://blog.aquasec.com/kubernetes-security-cve-2018-1002105

Mitigations
"""""""""""

- Access to the notebook is protected by authentication.
  An attacker therefore first has to compromise a Science Platform user and then use their credentials to access the notebook, or trick a Science Platform user into running attacker code.
  However, as noted in :ref:`the summary <summary>`, it is inevitable that a Science Platform user will be compromised at some point during the project and an attacker will be able to gain notebook access.
- The Interim Data Facility runs under Google Kubernetes Engine using Google Compute Engine VMs for the nodes and a hardened image, which reduces both the attack surface for privilege escalation from a pod and the access an attacker would have after achieving that privilege escalation.
- Users may notice and notify Rubin Observatory staff of attacker use of their notebooks.
- The Kubernetes control plane and nodes at the Interim Data Facility are automatically patched for security vulnerabilities via a release channel.

Recommendations
"""""""""""""""

The primary defense is the same as the first recommended for :ref:`security patching <gap-patching>`, namely:

- Ensure that the regular automated upgrades of the Kubernetes control plane and nodes is maintained in the transition from the Interim Data Facility to the final US Data Facility.

We should also continue running hardened images with layered security on the Kubernetes nodes.

In addition:

- Isolate user Notebook Aspect pods on their own hosts that are not shared with other Science Platform services.
  Then, if an attacker manages to escalate permissions from a Notebook Aspect pod, they would still be in a restricted environment that would limit lateral movement to anything other than Notebook Aspect pods that would be under similar restrictions.
- Collect system logs from Notebook Aspect pod hosts and alert on unexpected errors that may be a sign of attempted privilege escalation.
- Collect Kubernetes API logs and alert on unexpected access patterns that may be a sign of attempted privilege escalation.

.. _gap-notebook-secrets:

Management of notebook secrets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Low**

When spawning user notebooks, the Notebook Aspect needs to inject various secrets into the notebook.
Currently, some of those secrets are injected via a ``ConfigMap`` that is also used to set environment variables for non-secret configuration parameters.
One example of such a secret is the user's authentication token, used to authenticate as that user to other Science Platform services.
This creates a few risks:

- Secrets are stored in a ``ConfigMap`` rather than a ``Secret``, and therefore may be exposed by APIs and readable by Kubernetes clients that should not be able to read secrets.
- These secrets are made available as environment variables and inherited by any code that the user runs in their notebook, which increases the chances they will be accidentally leaked by the user to untrusted code.
  This is not a strong security boundary, since the secrets would be readable by the user in the file system regardless, but it could make casual discovery or leakage of secrets easier.

Mitigations
"""""""""""

- We are not aware of a Science Platform service that treats ``ConfigMap`` substantially differently than ``Secret``.
- The Notebook Aspect is an arbitrary code execution environment by design, and everything running in that environment will have access to the user's notebook secrets, so the method of communicating the secrets isn't a meaningful security boundary to protect.

Recommendations
"""""""""""""""

This is not a significant concern.
It's noted here primarily for completeness, and in case we later discover a reason why this is more of an issue than it immediately appeared.

That said, the spawning process for user notebooks should be modified to

- use ``Secret`` to communicate secrets, and
- mount those secrets on file system paths rather than injecting them as environment variables.

This will require modifying libraries that use those secrets to use the file system paths instead.

Implementing the design in SQR-066_ will address the first recommendation and make addressing the second recommendation easier.

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
  Ideally, it should also be tested with fuzzing.
- All user-facing API code should be reviewed by at least one person other than the author, with a eye specifically to potential security vulnerabilities.
- Where resources permit, the user-facing API surface and input validation of the most prominent Science Platform services should get a thorough code review by someone with experience in secure coding practices.
  However, this type of review can be time-consuming, and it's not realistic to ask the project to block on this review.

.. _gap-data-handling:

Safe data handling
^^^^^^^^^^^^^^^^^^

**Risk: Low**

Some components of the Science Platform may process User Generated data.
Carefully crafted data could be used to attack vulnerabilities in those components.
For example, image processing libraries are notorious for vulnerabilities when processing malicious images, leading to arbitrary code execution.

Mitigations
"""""""""""

- Data processing is only available to authorized users, so attacking these vulnerabilities would first require compromising the credentials of a Science Platform user.
- Vulnerabilities of this type will often be specific to astronomy software and would therefore require targeted research or at least fuzzing to exploit.
  Given the relatively low value of the data an attacker would be able to obtain by doing so, attackers with sufficient resources to properly attack astronomy software are unlikely to bother.
- Most user data processing will likely be done in environments where the user will already have arbitrary code execution by design (notebooks, batch processing systems), and thus these vulnerabilities would not matter.

Recommendations
"""""""""""""""

This type of attack is relatively low risk given the threat model for the science platform.
The scope would be limited to components that process user data without providing arbitrary code execution by design.
The lateral movement in the environment an attacker could obtain via this sort of attack is therefore unlikely to grant them substantially new access or capabilities.

That said, Rubin Observatory should take reasonable precautions against obvious and trivial attacks:

- Regularly upgrade underlying third-party libraries to pick up security fixes.
  See :ref:`security patching <gap-patching>` for more details.
- Where possible, validate user input before beginning processing, as described in :ref:`input validation <gap-input>`.
  However, this may not be feasible with complex data formats.

.. _gaps-web-security:

Web security
------------

.. _gap-csrf:

CSRF and credential leakage
^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: High**

Not all Science Platform services are hardened against cross-site request forgery (CSRF) from external sites.
All Science Platform services are vulnerable to CSRF attacks from other (possibly compromised) Science Platform services because they all share a JavaScript origin.

The current design for authentication for the Rubin Science Platform leaks cookies and user tokens to backend services.
This undermines isolation between services, which could become relevant if a service is compromised.

See `DMTN-193`_ for a complete discussion of web security concerns for the Science Platform.
See `SQR-051`_ for additional discussion of credential leakage.

.. _SQR-051: https://sqr-051.lsst.io/

Mitigations
"""""""""""

- Credentials are only leaked to Science Platform services and, absent another vulnerability, there is no known way for a user to get direct access to the leaked credentials of another user.
  (That said, there may be ways we don't know about given the lack of web security hardening of the Notebook Aspect.)

Recommendations
"""""""""""""""

Implement the recommendations described in `DMTN-193`_.

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

See `DMTN-193`_ for more discussion of this and other web security issues with the Science Platform.

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

See `DMTN-193`_ for additional discussion of these recommendations.

.. _gaps-authentication:

Authentication
--------------

.. _gap-api-credentials:

API credential theft
^^^^^^^^^^^^^^^^^^^^

Users of the Science Platform will be able to create API credentials that allow access to Science Platform APIs their local endpoints.
Those credentials will be used in user-written programs and local software, including to copy data and programs from the user's local system to the file system available to the Notebook and Portal Aspects.

Similar credentials will be managed by the user's web browser for access to web UIs such as the Notebook and Portal Aspects, but API credentials pose some additional security concerns.
Rather than being stored in the user's browser automatically, they're given to the user to enter into other applications or reference in code.
Not all users understand the importance of keeping these credentials confidential or understand how to do so.
For example, it is common to find API credentials checked into source control repositories, which are then subsequently pushed to public repositories such as on GitHub.
Attackers then automate the process of scanning public repositories for usable credentials.

As a trade-off between security and usability, the Science Platform API credentials will also not expire until revoked.
This increases the risk of old, unused, but still valid credentials being leaked via improper storage and later exploited by an attacker.

Mitigations
"""""""""""

- Science Platform API credentials will not have access to data that is high-value for an attacker, and are therefore unlikely to be added to custom scanners.
- It's less obvious from the credential how to use a Science Platform API credential compared to credentials for common cloud services such as AWS or Slack.
  That said, the code with which the credential was found will often provide a clue.

Recommendations
"""""""""""""""

This risk cannot be eliminated entirely without eliminating API credentials, which are a project requirement.
However, Rubin Observatory can take some steps to limit the risk.

- Provide clear instructions when providing an API credential to a user for how to store it, and caution against committing it to source control.
- Create guided flows for common reasons for creating API credentials that restrict the scope of the credential to only the services for which it is intended.
  This will limit the scope of any accidental exposure of the API credential.
- Provide users with information about their API credentials, from where they are being used, and when they were last used.
  Encourage users to clean up unused credentials and report unexpected credential use for further investigation.
- Ensure most sensitive actions, such as changing which federated identities a user can use to authenticate, will only be accessible via a web interface and cannot be changed using API credentials.

.. _gap-idp-compromise:

Identity provider compromise
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Low**

The Science Platform relies on federated identity and authentication via CILogon.
This allows the Science Platform to avoid storing or managing passwords, which has numerous security and non-security advantages.
However, it also means that the Science Platform delegates the security of its primary authentication system to third parties.
This is true both of user access and of administrative access.

Those providers fall roughly into three categories:

- `CILogon`_, which provides the core authentication service.
- Google and GitHub, commercial identity providers, which are expected to be widely chosen as authentication methods by project users and administrators.
- Individual home institutions of users, via the `InCommon`_, `eduGAIN`_, and `ORCID`_ federations.

.. _CILogon: https://www.cilogon.org/faq
.. _InCommon: https://www.incommon.org/
.. _eduGAIN: https://edugain.org/
.. _ORCID: https://orcid.org/

A compromise of CILogon would allow an attacker to impersonate any user of the Science Platform, including administrators.
Compromise of the other providers would allow an attacker to impersonate any user that uses one of those providers.
Compromise of the identity provider of any institution with data rights would allow an attacker to create a new account on the Science Platform without compromising an existing user, which decreases the risk of attacker detection.

If one identity provider in one of the federations is compromised, it is possible that Rubin Observatory would not learn of that compromise and thus not know to check for unexpected activity from users whose Science Platform accounts are linked to that identity provider.

Mitigations
"""""""""""

- Each of these identity providers are widely used for purposes other than the Science Platform.
  Compromise of any of these identity providers would affect web authentication for the institution running that identity provider, and would likely cause larger and more immediate problems for that institution than for the Science Platform.
  Each institution therefore has its own security team that is likely to notice and fix such compromises.
- Google and GitHub are used by tens of millions of users or more and have world-class security and incident response teams.
  Their security response to any incident will be far more effective than the response that Rubin Observatory could mount.
- CILogon is similarly widely used for purposes other than the Science Platform and has its own security support.

Recommendations
"""""""""""""""

To a large extent, this is a risk that Rubin Observatory should accept.
Delegating authentication to third parties that specialize in that (CILogon, GitHub, Google) or that have to provide the authentication service and security support for it for other reasons (federated institutions) is much less risky than maintaining a Science-Platform-specific authentication system.
However, Rubin Observatory should attempt to reduce the risk of impact from compromises that the project is not informed of.

- Work with CILogon to see if there is a notification list to which Rubin Observatory could subscribe to be informed of known security breaches in federated authentication providers.
- Notify Science Platform users of previous authentications, particularly from unexpected locations, to allow them to recognize and notify Rubin Observatory of possible compromises.

.. _gaps-abuse:

Abuse
-----

This section discusses abuse of the Science Platform for purposes outside of its intended use.
This abuse would not necessarily be done by a legitimate user.
As discussed elsewhere, it is inevitable that some users of the Science Platform will have their credentials compromised.
It's common for attackers, particularly those whose motives are to embarrass the project or claim credit for compromising a prominent site, to use access gained via a compromise to use computing resources for fraudulent, illegal, or undesired activities.

.. _gap-abuse-content:

Misuse of storage and network
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Risk: Low**

Attackers whose goal is to embarrass a project (due, for instance, to its affiliation with a political entity) or to claim credit for compromising a prominent site will often deface the site or use it to host illegal or unwanted content.
Attackers also use access to web services to host malware or phishing pages to aid in compromising other sites.
While this sort of attacker activity is unlikely to cause permanent damage, unlike ransomware, it can be embarrassing and disruptive to the project.
Use of Science Platform resources by an attacker to serve illegal content also creates risk that Science Platform facilities would be entangled in legal action, on top of the obvious desire of the project to prevent illegal activity.

Most public-facing web pages for the project are not hosted on the Science Platform.
The Science Platform is intended for the smaller community of authorized users.
It is therefore not a major target for web site defacement.
`SQR-037`_ contains some discussion of web site defacement in the context of community.lsst.org, which is a more attractive target.

The top concern in this area is attackers using Science Platform credentials to store and share illegal content.
The most likely ways an attacker could do this is via outbound connections from the notebook (such as BitTorrent), or via sharing of user credentials to the same notebook environment.

Mitigations
"""""""""""

- The Science Platform does not provide web hosting available to users.
  An attacker would therefore need to compromise the infrastructure, not just a user account, to deface web sites or host web pages.
- The Notebook Aspect doesn't allow inbound connections to the notebook, so using the notebook to serve malicious content would be difficult.
- The number of legitimate Science Platform users is relatively low.
  Attackers whose goal is to share illegal content normally target platforms with millions of users and large numbers of abandoned accounts, since that increases the chances that they can successfully evade detection.

Recommendations
"""""""""""""""

- Limit outgoing bandwidth from notebooks.
  The expected use of outbound Internet connections from notebooks is primarily to download software.
  Lots of outbound data would generally be unexpected and a possible sign of abuse.
- Detect and alert on accounts with successful authentications from a wide variety of IP addresses.
  This is a tell-tale sign of a compromised account and possible account sharing.
  The alerts have to be thoughtfully constructed since users do travel (including internationally).
- Provide GeoIP information to the user about the locations from which they previously authenticated.
  Encourage the user to report unexpected access.
  This is difficult to do well since GeoIP databases have to be purchased and are still of fairly low quality.
- Monitor outbound Internet connections from pods and flag for investigation connections that seem unrelated to astronomy research.
  For instance, a notebook is unlikely to have a legitimate need to connect to a BitTorrent rendezvous service or to join a Tor network.

.. _gap-abuse-compute:

Misuse of compute resources
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The popularity and value of proof-of-work-based cryptocurrencies has given rise to a new attacker goal: Access to compute resources to run a cryptocurrency miner.
This is less likely to be a primary goal than something an attacker may do with access while looking around for other interesting targets.
Platforms designed for highly-optimized computation, particularly ones with GPUs available, are more attractive targets for this purpose than general-purpose computing.
Attackers would therefore be more interested in a batch computing service for this purpose than the Notebook Aspect, although may run a miner on the Notebook Aspect after a successful compromise because the effort required is minimal.

Mitigations
"""""""""""

- Effective cryptocurrency mining increasingly requires dedicated hardware and resources that are beyond the scale of what the Notebook Aspect would have available.
  The payoff of cryptocurrency mining in the notebook is less likely to be worth the effort.
- Batch computing services may have less access to the Internet, which would limit their usability for cryptocurrency mining.

Recommendations
"""""""""""""""

This area is less interesting as a direct risk than as a possible attacker goal that could be used to detect an attacker and cut off their access before they do something else more dangerous.

- Shut down pods that consume excessive CPU resources and report that to the pod's owner.
  The pod owner may then realize that their account has been compromised.
  Rubin Observatory will want to monitor CPU usage anyway, for the much more likely problem of poorly-written code or code that tries to process unexpectedly large amounts of data.

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

Mitigations
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

Supply-chain attacks
--------------------

Attackers are increasingly attempting to compromise widely-shared library and resource repositories, such as PyPI, NPM, and Docker Hub.
If they are successful in doing so, they can inject malicious code into many downstream users of those services.
This is particularly a risk when automatically deploying new upstream versions of dependencies.
However, this risk is very hard to defend against.

Rubin Observatory does not have the resources to audit and rebuild all dependencies locally or otherwise isolate itself from public code and resource repositories.
Any successful attack of this type is likely to make headlines, and Rubin Observatory can then take remedial action retroactively.
Attempting to defend against this attack proactively is unlikely to be successful given existing resources and is unlikely to uniquely affect the project (and thus does not pose a substantial reputational risk to the project).

We should therefore accept this risk.

Use of Kubernetes secrets
-------------------------

Kubernetes has a built-in secret management interface using ``Secret`` objects.
This interface provides easy injection of secrets into pods and use of the Kubernetes API to pass secrets between applications.
It is also well-supported by third-party applications that integrate with long-term secret stores, such as Vault_ (via Vault Secrets Operator_).

.. _Vault: https://www.vaultproject.io/
.. _Vault Secrets Operator: https://github.com/ricoberger/vault-secrets-operator

The drawback of Kubernetes secrets is that they're stored in the Kubernetes control plane, are accessible to any Kubernetes user with the necessary permissions, may or may not be encrypted at rest, and can easily be stolen if the Kubernetes control plane is compromised.
They are also readily accessible via Kubernetes APIs that may be inobvious, such as by launching a pod in the same namespace and requesting the secret be mounted in the pod.
Secrets are also provided to the pod via either environment variables or mounted files, both of which are easily accessible to all processes running in the pod.

More sophisticated systems such as Vault can offer more protection for secrets if used directly instead of via Kubernetes secrets.
Such systems lend themselves to being used with more care, such as by retrieving secrets only when necessary, storing them only in memory of a given process, and discarding them when they're no longer needed.

However, the additional risk of using Kubernetes secrets is small and comparable to other risks around credential management that we're already accepting.
The cost of a more sophisticated secret management system is relatively high, requiring injecting custom code into most applications and, depending on how thoroughly an alternate policy would be implemented, modifying third-party software used by the Rubin Science Platform.

Given the relatively low risk and relatively high cost of alternatives, we should accept this risk.

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

References
==========

- `Threat matrix for Kubernetes <https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/>`__ and its update, `Secure containerized environments with updated threat matrix for Kubernetes <https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/>`__.
- `CIS Google Kubernetes Engine (GKE) Benchmark v1.2.0 <https://www.cisecurity.org/>`__

Changes
=======

2021-12-17
----------

- Move the risks of the Notebook Aspect into their own section.
- Move the risk of granting Kubernetes access to Dask to its own section (:ref:`Dask access for notebooks <gap-dask>`) and mark it as high.
  Downgrade the remaining :ref:`Notebook privilege escalation <gap-escalation>` risk to low given the mitigations available in the Interim Data Facility.
- Add :ref:`Management of notebook secrets <gap-notebook-secrets>` and mark it as low risk.
- Add :ref:`CSRF and credential leakage <gap-csrf>` and mark it as high.
  Reference `DMTN-193`_ for a complete discussion of web security concerns for the Science Platform.
- Downgrade the :ref:`Kubernetes hardening <gap-kubernetes>` risk to medium thanks to the hardening work that has been completed.
  Add additional recommendations after reviewing more Kubernetes security analyses.
- Recommend using the new GitHub OpenID Connect support for Terraform authentication.
- Update the analysis in multiple places to reflect the Interim Data Facility deployment and the upcoming US Data Facility deployment.
- Update the analysis of :ref:`Security patching <gap-patching>` to reflect completed work.

2020-08-21
----------

- Update analysis, mitigations, and recommendations for the work that was done on :ref:`Security patching <gap-patching>`.
- Add :ref:`Kubernetes hardening <gap-kubernetes>` and mark it as one of the highest risk areas.
- Update :ref:`Notebook attacks on servces <gap-notebook-cluster>` to recommend enabling network policy enforcement and adding network policies to restrict what services Notebook Aspect pods can access.
