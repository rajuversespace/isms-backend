/// Seed policy definition.
pub struct SeedPolicy {
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
}

/// Default ISMS policies (26 total).
pub static DEFAULT_POLICIES: &[SeedPolicy] = &[
    // ISMS Core
    SeedPolicy { name: "ISMS Scope", version: "1.0", description: "Defines the boundaries and applicability of the Information Security Management System." },
    SeedPolicy { name: "Information Security Policy", version: "1.0", description: "Sets out the organization's overall commitment to information security." },
    SeedPolicy { name: "Information Security Roles and Responsibilities", version: "1.0", description: "Defines information security roles and the responsibilities assigned to each role." },
    SeedPolicy { name: "Risk Assessment and Risk Treatment Process", version: "1.0", description: "Describes the methodology for identifying, analysing, evaluating, and treating information security risks." },
    SeedPolicy { name: "Statement of Applicability", version: "1.0", description: "Documents which ISO 27001 Annex A controls are applicable or excluded, with justifications." },
    SeedPolicy { name: "Information Security Objectives Plan", version: "1.0", description: "Defines measurable information security objectives and the plans to achieve them." },
    SeedPolicy { name: "Master List of Documents", version: "1.0", description: "The authoritative register of all ISMS controlled documents." },
    SeedPolicy { name: "Procedure for Control of Documented Information", version: "1.0", description: "Defines how ISMS documents are created, reviewed, approved, and version-controlled." },
    SeedPolicy { name: "Procedure for Internal Audits", version: "1.0", description: "Defines the process for planning and conducting internal ISMS audits." },
    SeedPolicy { name: "Procedure for Management Review", version: "1.0", description: "Defines the agenda, inputs, outputs, and frequency of management review meetings." },
    SeedPolicy { name: "Procedure for Corrective Action and Continual Improvement", version: "1.0", description: "Defines how nonconformities are identified, root-cause analysed, and corrected." },
    SeedPolicy { name: "Relevant Laws, Regulations and Contractual Requirements", version: "1.0", description: "Register of applicable legal, statutory, regulatory, and contractual obligations." },
    // Technical & Operational
    SeedPolicy { name: "Access Control Policy", version: "1.0", description: "Defines least privilege, user provisioning, privileged access management, and MFA requirements." },
    SeedPolicy { name: "Asset Management Policy", version: "1.0", description: "Defines requirements for asset inventory, classification, labelling, and acceptable use." },
    SeedPolicy { name: "Risk Management Policy", version: "1.0", description: "Defines how information security risks are identified, assessed, and treated." },
    SeedPolicy { name: "Cryptography Policy", version: "1.0", description: "Defines rules for cryptographic controls including encryption algorithms and key management." },
    SeedPolicy { name: "Data Management Policy", version: "1.0", description: "Defines data classification levels, handling rules, retention schedules, and secure deletion." },
    SeedPolicy { name: "Incident Response Plan", version: "1.0", description: "Defines the process for detecting, containing, eradicating, and recovering from security incidents." },
    SeedPolicy { name: "Operations Security Policy", version: "1.0", description: "Defines operational security controls covering change management, patching, logging, and monitoring." },
    SeedPolicy { name: "Physical Security Policy", version: "1.0", description: "Defines physical access controls, secure area requirements, and clean desk rules." },
    SeedPolicy { name: "Secure Development Policy", version: "1.0", description: "Defines secure coding practices, security in the SDLC, and separation of environments." },
    SeedPolicy { name: "Third-Party Management Policy", version: "1.0", description: "Defines due-diligence requirements for vendors and suppliers." },
    // People & HR
    SeedPolicy { name: "Human Resource Security Policy", version: "1.0", description: "Defines background screening, security training obligations, and off-boarding procedures." },
    SeedPolicy { name: "Code of Conduct", version: "1.0", description: "Defines standards of professional conduct and acceptable use of company systems." },
    // Specialised
    SeedPolicy { name: "Business Continuity and Disaster Recovery Plan", version: "1.0", description: "Defines RTO/RPO targets, recovery strategies, and return-to-operations steps." },
    SeedPolicy { name: "Data Protection and Security Training Policy", version: "1.0", description: "Defines mandatory security awareness training requirements and frequency." },
    SeedPolicy { name: "Whistleblower Policy", version: "1.0", description: "Defines the confidential reporting channel for suspected security violations." },
];
