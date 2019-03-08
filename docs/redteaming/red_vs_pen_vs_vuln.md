# Red Teaming VS Penetration Testing VS Vulnerability Testing

A threat based approach to security testing may use several names; Red Teaming, Threat Operations, Threat Assessment, Purple Teaming, Adversarial Assessment, Penetration Testing, Vulnerability Testing. These are not all the same, and it is important that the security industry defines terms to establish a common understanding. To help with this, all threat-based security testing in this post will be referred to as Red Teaming.

>Definition: Red Teaming is the process of using tactics, techniques, and procedures (TTPs) to emulate a real-world threat with the goals of training and measuring the effectiveness of people, processes, and technology used to defend an environment.

In other words, red teaming is the process of emulating a threat using real threat techniques with the goal of training blue teams and/or measuring security operations as a whole.

Red teaming can provide a deep understand the impacts an intelligent threat-actor can have against a target.

Using an inverse pyramid, we can illustrate the relationships between Red Teaming, Penetration Testing, and Vulnerability Assessments. This will help further define what Red Teaming IS and IS NOT.

![](/images/threat_pyramid.png)

__Vulnerability assessments__ tend to be wide in coverage but narrow in scope. Consider a vulnerability assessment of all enterprise workstations. The scope is very wide, but not very deep in context of organizational risks. What can be said about risk when flaws are found? Organizational risk can only be understood at the workstation level. Overall risk to an organization may be extrapolated to a small degree, but generally stays at that workstation level. Vulnerability assessment are good at reducing the attack surface but do not provide much detail in terms of organizational risk.

__Penetrations tests__ take vulnerability assessments to the next level by exploiting and proving out attack paths. Penetration tests can often look and feel like a red team engagement and even use some of the same tools or techniques. The key difference lies in the goals and intent. The goal of a penetration test is to execute an attack against a target system to identify and measure risks associated with the exploitation of a target’s attack surface. Organizational risks can be indirectly measured and are typically extrapolated from some technical attack. What about the people and processes? This is where red teaming fits. Red teaming focuses on security operations as a whole and includes people, processes, and technology. Red teaming specifically focuses on goals related to training blue teams or measuring how security operations can impact a threat’s ability to operate. Technical flaws are secondary to understanding how the threat was able to impact an organization’s operations or how security operations was able to impact a threat’s ability to operate.

## References

[Threat Gets a Vote - Applying a threat based approach to security testing](http://threatexpress.com/blogs/2018/threat-gets-a-vote-applying-a-threat-based-approach-to-security-testing/)

[Red Teaming Definition: SANS SEC 564 Red Team Operations and Threat Emulation](https://sans.org/sec564)