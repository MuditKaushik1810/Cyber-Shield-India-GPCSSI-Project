"""Cyber Shield India — Threat Intelligence Platform (TIP) static registry.

A centralized, deterministic cross-referencing matrix powering the asset-centric
TIP pivot of the Strategic Threat Analytics dashboard. Three datasets live here:

* :data:`STATE_INTELLIGENCE_METRIC` — every Indian State (28) and Union Territory
  (8) mapped to its cyber nodal cell, reporting portal and a 3-vector live threat
  matrix (severity / trend / governing bulletin, with an optional tag linking each
  vector to the global tag taxonomy for cross-referenced filtering).
* :data:`THREAT_TAGS` — the scam-mechanism tag taxonomy (``#DigitalArrest`` …)
  that cross-references regulatory advisories, expert signals and the Victim
  Triage playbook category for a given vector.
* :data:`EXPERT_SIGNALS` — a curated feed of public awareness posts from named
  cyber experts and city/state cyber cells, tagged to the same taxonomy.

Everything is static and side-effect-free, so the dashboard can filter across all
three in lock-step from a single ``st.session_state`` tag selection.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

NCRP_HELPLINE: str = "1930"
NCRP_PORTAL: str = "https://cybercrime.gov.in"


# --------------------------------------------------------------------------- #
# 1. State & Union Territory directory (28 States + 8 UTs).                   #
# --------------------------------------------------------------------------- #


_CERTIN: str = "https://www.cert-in.org.in"
_I4C: str = "https://i4c.mha.gov.in"
_RBI: str = "https://www.rbi.org.in/Scripts/BS_PressReleaseDisplay.aspx"
_TRAI: str = "https://www.trai.gov.in"
_SANCHAR: str = "https://www.sancharsaathi.gov.in"
_NCRB: str = "https://www.ncrb.gov.in"
_NCIIPC: str = "https://nciipc.gov.in"

# Jurisdictions classified as Union Territories (the rest are States).
_UNION_TERRITORIES: frozenset = frozenset({
    "Andaman & Nicobar Islands", "Chandigarh",
    "Dadra and Nagar Haveli and Daman and Diu", "Delhi", "Jammu and Kashmir",
    "Ladakh", "Lakshadweep", "Puducherry",
})

# Authoritative national directory: every State (28) and Union Territory (8)
# mapped to its cyber nodal cell, reporting portal, and a 3-vector live threat
# matrix. Each vector carries a severity band, a directional trend, the governing
# official bulletin, and (where it maps onto the global tag taxonomy) a "tag" key
# enabling cross-referencing with the dashboard tag-selection system.
STATE_INTELLIGENCE_METRIC: Dict[str, Dict[str, object]] = {'Andhra Pradesh': {'cell_name': 'AP Police Cyber Crime Wing',
                    'portal': 'https://cybercrime.gov.in',
                    'threat_matrix': {'Aadhaar-Enabled Payment System (AePS) Spoofing': {'severity': 'CRITICAL',
                                                                                         'trend': '📈 '
                                                                                                  'Upward '
                                                                                                  'Spike',
                                                                                         'bulletin': 'I4C '
                                                                                                     'Unified '
                                                                                                     'Advisory '
                                                                                                     'on '
                                                                                                     'Biometric '
                                                                                                     'Lock '
                                                                                                     'Controls',
                                                                                         'tag': '#AadhaarBiometricSpoofing'},
                                      'Digital Arrest Coercion Calls': {'severity': 'HIGH',
                                                                        'trend': '📈 Upward Spike',
                                                                        'bulletin': 'I4C Alert '
                                                                                    'on '
                                                                                    'Nation-Wide '
                                                                                    "'Digital "
                                                                                    "Arrest' "
                                                                                    'Threat '
                                                                                    'Patterns',
                                                                        'tag': '#DigitalArrest'},
                                      'Stock Investment Advisory Fraud': {'severity': 'MEDIUM',
                                                                          'trend': '➡️ Stable',
                                                                          'bulletin': 'SEBI & '
                                                                                      'I4C Joint '
                                                                                      'Warning '
                                                                                      'on '
                                                                                      'Illegal '
                                                                                      'Trading '
                                                                                      'Platforms',
                                                                          'tag': '#InvestmentScam'}}},
 'Arunachal Pradesh': {'cell_name': 'Arunachal Pradesh Cyber Crime Cell',
                       'portal': 'https://arunpol.gov.in',
                       'threat_matrix': {'Malicious Instant Loan App Exploitation': {'severity': 'HIGH',
                                                                                     'trend': '📈 '
                                                                                              'Upward '
                                                                                              'Spike',
                                                                                     'bulletin': 'MHA '
                                                                                                 'Guidelines '
                                                                                                 'on '
                                                                                                 'Extortionate '
                                                                                                 'Lending '
                                                                                                 'Channels',
                                                                                     'tag': '#LoanAppHarassment'},
                                         'Fake Government Subsidy & DBT Disbursal': {'severity': 'MEDIUM',
                                                                                     'trend': '➡️ '
                                                                                              'Stable',
                                                                                     'bulletin': 'CERT-In '
                                                                                                 'Threat '
                                                                                                 'Bulletin '
                                                                                                 'on '
                                                                                                 'Regional '
                                                                                                 'Phishing '
                                                                                                 'Infrastructure'},
                                         'SIM-Swap OTP Interception': {'severity': 'HIGH',
                                                                       'trend': '📈 Upward Spike',
                                                                       'bulletin': 'DoT Order on '
                                                                                   'Bulk-SIM '
                                                                                   'Deactivation '
                                                                                   'Modules',
                                                                       'tag': '#SIMSwapFraud'}}},
 'Assam': {'cell_name': 'Assam CID Cyber Crime Cell & NDISC (Assam Node)',
           'portal': 'https://cid.assampolice.gov.in',
           'threat_matrix': {'Fake Government Subsidy & DBT Disbursal Schemes': {'severity': 'HIGH',
                                                                                 'trend': '📈 '
                                                                                          'Upward '
                                                                                          'Spike',
                                                                                 'bulletin': 'CERT-In '
                                                                                             'Threat '
                                                                                             'Bulletin '
                                                                                             'on '
                                                                                             'Regional '
                                                                                             'Phishing '
                                                                                             'Infrastructure'},
                             'Malicious Instant Loan App Extortion': {'severity': 'HIGH',
                                                                      'trend': '➡️ Stable',
                                                                      'bulletin': 'MHA '
                                                                                  'Guidelines on '
                                                                                  'Extortionate '
                                                                                  'Lending '
                                                                                  'Channels',
                                                                      'tag': '#LoanAppHarassment'},
                             'Digital Arrest Coercion Calls': {'severity': 'MEDIUM',
                                                               'trend': '📈 Upward Spike',
                                                               'bulletin': 'I4C Alert on '
                                                                           "Nation-Wide 'Digital "
                                                                           "Arrest' Threat "
                                                                           'Patterns',
                                                               'tag': '#DigitalArrest'}}},
 'Bihar': {'cell_name': 'Economic Offences Unit (EOU) Cyber Cell',
           'portal': 'https://eou.bihar.gov.in',
           'threat_matrix': {'Mule Account Network Aggregation & Rental Fraud': {'severity': 'CRITICAL',
                                                                                 'trend': '📈 '
                                                                                          'Upward '
                                                                                          'Spike',
                                                                                 'bulletin': 'RBI '
                                                                                             'Notification '
                                                                                             'on '
                                                                                             'Coordinated '
                                                                                             'Crackdowns '
                                                                                             'on '
                                                                                             'Layered '
                                                                                             'Banking'},
                             'UPI Collect-Request Reversal': {'severity': 'HIGH',
                                                              'trend': '📈 Upward Spike',
                                                              'bulletin': 'NCRP Operative '
                                                                          'Protocol on Immediate '
                                                                          'UPI Transaction Halts',
                                                              'tag': '#UPICollectScam'},
                             'Bank KYC Screen-Mirroring Fraud': {'severity': 'HIGH',
                                                                 'trend': '➡️ Stable',
                                                                 'bulletin': 'DoT Order on '
                                                                             'Bulk-SIM '
                                                                             'Deactivation '
                                                                             'Modules'}}},
 'Chhattisgarh': {'cell_name': 'Chhattisgarh Police State Cyber Forensic Division',
                  'portal': 'https://cgpolice.gov.in',
                  'threat_matrix': {'Part-Time Remote Work & Telegram Task Scams': {'severity': 'HIGH',
                                                                                    'trend': '📈 '
                                                                                             'Upward '
                                                                                             'Spike',
                                                                                    'bulletin': 'I4C '
                                                                                                'Strategic '
                                                                                                'Advisory '
                                                                                                'on '
                                                                                                'Deceptive '
                                                                                                'Digital '
                                                                                                'Recruiters'},
                                    'High-Yield Crypto Deposit Scam': {'severity': 'HIGH',
                                                                       'trend': '➡️ Stable',
                                                                       'bulletin': 'RBI Circular '
                                                                                   'on '
                                                                                   'Unregulated '
                                                                                   'Electronic '
                                                                                   'Investment '
                                                                                   'Schemes',
                                                                       'tag': '#InvestmentScam'},
                                    'Malicious Loan App Harassment': {'severity': 'MEDIUM',
                                                                      'trend': '📉 Downward Shift',
                                                                      'bulletin': 'MHA '
                                                                                  'Guidelines on '
                                                                                  'Extortionate '
                                                                                  'Lending '
                                                                                  'Channels',
                                                                      'tag': '#LoanAppHarassment'}}},
 'Goa': {'cell_name': 'Goa Police Cyber Crime Cell HQ',
         'portal': 'https://goapolice.gov.in',
         'threat_matrix': {'Fake Travel & Luxury Villa Booking Exploitations': {'severity': 'HIGH',
                                                                                'trend': '📈 '
                                                                                         'Upward '
                                                                                         'Spike',
                                                                                'bulletin': 'TRAI '
                                                                                            'Directives '
                                                                                            'on '
                                                                                            'Malicious '
                                                                                            'Domain '
                                                                                            'Blacklisting'},
                           'UPI QR-Code Redirection Scam': {'severity': 'MEDIUM',
                                                            'trend': '➡️ Stable',
                                                            'bulletin': 'NCRP Operative Protocol '
                                                                        'on Immediate UPI '
                                                                        'Transaction Halts',
                                                            'tag': '#UPICollectScam'},
                           'Sextortion Honeytrap Rings': {'severity': 'HIGH',
                                                          'trend': '📈 Upward Spike',
                                                          'bulletin': 'National Cyber Security '
                                                                      'Strategy on Honeypot '
                                                                      'Operations'}}},
 'Gujarat': {'cell_name': 'State Cyber Crime Cell, CID Crime Gandhinagar',
             'portal': 'https://gujaratcybercrime.org',
             'threat_matrix': {'Stock Market Investment & Algorithmic Trading Spoofs': {'severity': 'CRITICAL',
                                                                                        'trend': '📈 '
                                                                                                 'Upward '
                                                                                                 'Spike',
                                                                                        'bulletin': 'SEBI '
                                                                                                    '& '
                                                                                                    'I4C '
                                                                                                    'Joint '
                                                                                                    'Warning '
                                                                                                    'on '
                                                                                                    'Illegal '
                                                                                                    'Trading '
                                                                                                    'Platforms',
                                                                                        'tag': '#InvestmentScam'},
                               'Digital Arrest Coercion Calls': {'severity': 'HIGH',
                                                                 'trend': '📈 Upward Spike',
                                                                 'bulletin': 'I4C Alert on '
                                                                             'Nation-Wide '
                                                                             "'Digital Arrest' "
                                                                             'Threat Patterns',
                                                                 'tag': '#DigitalArrest'},
                               'Customs Courier Parcel Scam': {'severity': 'MEDIUM',
                                                               'trend': '➡️ Stable',
                                                               'bulletin': 'I4C Alert on Courier '
                                                                           'Contraband Extortion',
                                                               'tag': '#FedExCourierScam'}}},
 'Haryana': {'cell_name': 'State Cyber Crime Bureau Haryana (Mewat JTF Node)',
             'portal': 'https://haryanapolice.gov.in',
             'threat_matrix': {'OLX Marketplace Escrow & QR Code Redirection Scams': {'severity': 'CRITICAL',
                                                                                      'trend': '📈 '
                                                                                               'Upward '
                                                                                               'Spike',
                                                                                      'bulletin': 'NCRP '
                                                                                                  'Operative '
                                                                                                  'Protocol '
                                                                                                  'on '
                                                                                                  'Immediate '
                                                                                                  'UPI '
                                                                                                  'Transaction '
                                                                                                  'Halts',
                                                                                      'tag': '#UPICollectScam'},
                               'Sextortion Video-Call Recording Traps': {'severity': 'HIGH',
                                                                         'trend': '📈 Upward '
                                                                                  'Spike',
                                                                         'bulletin': 'National '
                                                                                     'Cyber '
                                                                                     'Security '
                                                                                     'Strategy '
                                                                                     'on '
                                                                                     'Honeypot '
                                                                                     'Operations'},
                               'Bank KYC Vishing & SIM Abuse': {'severity': 'HIGH',
                                                                'trend': '➡️ Stable',
                                                                'bulletin': 'DoT Order on '
                                                                            'Bulk-SIM '
                                                                            'Deactivation '
                                                                            'Modules',
                                                                'tag': '#SIMSwapFraud'}}},
 'Himachal Pradesh': {'cell_name': 'HP Police Cyber Crime CID Division Shimla',
                      'portal': 'https://cidhp.gov.in',
                      'threat_matrix': {'Work-From-Home Crypto Arbitrage Arbitrations': {'severity': 'HIGH',
                                                                                         'trend': '📈 '
                                                                                                  'Upward '
                                                                                                  'Spike',
                                                                                         'bulletin': 'NCIIPC '
                                                                                                     'Advisory '
                                                                                                     'on '
                                                                                                     'Endpoint '
                                                                                                     'Exploits '
                                                                                                     'Targeting '
                                                                                                     'Infrastructure'},
                                        'Task-Based Telegram Recruiter Scam': {'severity': 'HIGH',
                                                                               'trend': '➡️ '
                                                                                        'Stable',
                                                                               'bulletin': 'I4C '
                                                                                           'Strategic '
                                                                                           'Advisory '
                                                                                           'on '
                                                                                           'Deceptive '
                                                                                           'Digital '
                                                                                           'Recruiters'},
                                        'Investment Deposit Fraud': {'severity': 'MEDIUM',
                                                                     'trend': '➡️ Stable',
                                                                     'bulletin': 'RBI Circular '
                                                                                 'on Unregulated '
                                                                                 'Electronic '
                                                                                 'Investment '
                                                                                 'Schemes',
                                                                     'tag': '#InvestmentScam'}}},
 'Jharkhand': {'cell_name': 'Jharkhand CID Cyber Crime Division (Jamtara Desk)',
               'portal': 'https://jhpolice.gov.in',
               'threat_matrix': {'Bank KYC Verification & App-Based Screen Mirroring Frauds': {'severity': 'CRITICAL',
                                                                                               'trend': '📈 '
                                                                                                        'Upward '
                                                                                                        'Spike',
                                                                                               'bulletin': 'DoT '
                                                                                                           'Order '
                                                                                                           'on '
                                                                                                           'Bulk-SIM '
                                                                                                           'Deactivation '
                                                                                                           'Modules'},
                                 'AePS Biometric Cloning': {'severity': 'HIGH',
                                                            'trend': '📈 Upward Spike',
                                                            'bulletin': 'I4C Unified Advisory on '
                                                                        'Biometric Lock Controls',
                                                            'tag': '#AadhaarBiometricSpoofing'},
                                 'UPI Phishing Link Distribution': {'severity': 'HIGH',
                                                                    'trend': '➡️ Stable',
                                                                    'bulletin': 'NCRP Operative '
                                                                                'Protocol on '
                                                                                'Immediate UPI '
                                                                                'Transaction '
                                                                                'Halts',
                                                                    'tag': '#UPICollectScam'}}},
 'Karnataka': {'cell_name': 'CID Cyber Crime Division Bengaluru (CEN Stations)',
               'portal': 'https://ksp.karnataka.gov.in',
               'threat_matrix': {'Business Email Compromise (BEC) & Deepfake CEO Impersonation': {'severity': 'CRITICAL',
                                                                                                  'trend': '📈 '
                                                                                                           'Upward '
                                                                                                           'Spike',
                                                                                                  'bulletin': 'MeitY '
                                                                                                              'Statutory '
                                                                                                              'Advisory '
                                                                                                              'on '
                                                                                                              'Synthetic '
                                                                                                              'Media '
                                                                                                              'Manipulations',
                                                                                                  'tag': '#DeepfakeFraud'},
                                 'Investment & Trading App Fraud': {'severity': 'HIGH',
                                                                    'trend': '📈 Upward Spike',
                                                                    'bulletin': 'SEBI & I4C '
                                                                                'Joint Warning '
                                                                                'on Illegal '
                                                                                'Trading '
                                                                                'Platforms',
                                                                    'tag': '#InvestmentScam'},
                                 'Digital Arrest Coercion Calls': {'severity': 'HIGH',
                                                                   'trend': '➡️ Stable',
                                                                   'bulletin': 'I4C Alert on '
                                                                               'Nation-Wide '
                                                                               "'Digital Arrest' "
                                                                               'Threat Patterns',
                                                                   'tag': '#DigitalArrest'}}},
 'Kerala': {'cell_name': 'Cyberdome Kerala Police Centre of Excellence',
            'portal': 'https://cyberdome.kerala.gov.in',
            'threat_matrix': {'Advanced Social Engineering & Sextortion Blackmail Rings': {'severity': 'CRITICAL',
                                                                                           'trend': '📈 '
                                                                                                    'Upward '
                                                                                                    'Spike',
                                                                                           'bulletin': 'Kerala '
                                                                                                       'Police '
                                                                                                       'Operational '
                                                                                                       'Guide '
                                                                                                       'on '
                                                                                                       'Digital '
                                                                                                       'Footprint '
                                                                                                       'Purging'},
                              'Malicious Loan App Extortion': {'severity': 'HIGH',
                                                               'trend': '➡️ Stable',
                                                               'bulletin': 'MHA Guidelines on '
                                                                           'Extortionate Lending '
                                                                           'Channels',
                                                               'tag': '#LoanAppHarassment'},
                              'Fake Job & Investment Lures': {'severity': 'MEDIUM',
                                                              'trend': '📈 Upward Spike',
                                                              'bulletin': 'I4C Strategic '
                                                                          'Advisory on Deceptive '
                                                                          'Digital Recruiters',
                                                              'tag': '#InvestmentScam'}}},
 'Madhya Pradesh': {'cell_name': 'MP State Cyber Police HQ Bhopal',
                    'portal': 'https://cybermp.gov.in',
                    'threat_matrix': {'Electricity Bill Expiry & Utility Disconnection Threats': {'severity': 'HIGH',
                                                                                                  'trend': '📈 '
                                                                                                           'Upward '
                                                                                                           'Spike',
                                                                                                  'bulletin': 'Power '
                                                                                                              'Ministry '
                                                                                                              'Advisory '
                                                                                                              'on '
                                                                                                              'Phishing '
                                                                                                              'SMS '
                                                                                                              'Gateways'},
                                      'Digital Arrest Coercion Calls': {'severity': 'HIGH',
                                                                        'trend': '📈 Upward Spike',
                                                                        'bulletin': 'I4C Alert '
                                                                                    'on '
                                                                                    'Nation-Wide '
                                                                                    "'Digital "
                                                                                    "Arrest' "
                                                                                    'Threat '
                                                                                    'Patterns',
                                                                        'tag': '#DigitalArrest'},
                                      'UPI Collect-Request Reversal': {'severity': 'MEDIUM',
                                                                       'trend': '➡️ Stable',
                                                                       'bulletin': 'NCRP '
                                                                                   'Operative '
                                                                                   'Protocol on '
                                                                                   'Immediate '
                                                                                   'UPI '
                                                                                   'Transaction '
                                                                                   'Halts',
                                                                       'tag': '#UPICollectScam'}}},
 'Maharashtra': {'cell_name': 'Maharashtra Cyber Security Command Center Mumbai',
                 'portal': 'https://mahacyber.gov.in',
                 'threat_matrix': {'Customs Courier Package Containment & Narcotic Accusation Scams': {'severity': 'CRITICAL',
                                                                                                       'trend': '📈 '
                                                                                                                'Upward '
                                                                                                                'Spike',
                                                                                                       'bulletin': 'I4C '
                                                                                                                   'Alert '
                                                                                                                   'on '
                                                                                                                   'Nation-Wide '
                                                                                                                   "'Digital "
                                                                                                                   "Arrest' "
                                                                                                                   'Threat '
                                                                                                                   'Patterns',
                                                                                                       'tag': '#FedExCourierScam'},
                                   'Digital Arrest Coercion Calls': {'severity': 'CRITICAL',
                                                                     'trend': '📈 Upward Spike',
                                                                     'bulletin': 'I4C Alert on '
                                                                                 'Nation-Wide '
                                                                                 "'Digital "
                                                                                 "Arrest' Threat "
                                                                                 'Patterns',
                                                                     'tag': '#DigitalArrest'},
                                   'Stock Investment & Trading Spoof': {'severity': 'HIGH',
                                                                        'trend': '➡️ Stable',
                                                                        'bulletin': 'SEBI & I4C '
                                                                                    'Joint '
                                                                                    'Warning on '
                                                                                    'Illegal '
                                                                                    'Trading '
                                                                                    'Platforms',
                                                                        'tag': '#InvestmentScam'}}},
 'Manipur': {'cell_name': 'Manipur State Cyber Crime PS',
             'portal': 'https://manipurpolice.gov.in',
             'threat_matrix': {'Identity Theft & Targeted Social Profile Hijacking': {'severity': 'HIGH',
                                                                                      'trend': '➡️ '
                                                                                               'Stable',
                                                                                      'bulletin': 'MHA '
                                                                                                  'Operational '
                                                                                                  'Guidelines '
                                                                                                  'on '
                                                                                                  'Communal '
                                                                                                  'Threat '
                                                                                                  'Mitigation'},
                               'Malicious Loan App Harassment': {'severity': 'MEDIUM',
                                                                 'trend': '📈 Upward Spike',
                                                                 'bulletin': 'MHA Guidelines on '
                                                                             'Extortionate '
                                                                             'Lending Channels',
                                                                 'tag': '#LoanAppHarassment'},
                               'SIM-Swap OTP Interception': {'severity': 'MEDIUM',
                                                             'trend': '➡️ Stable',
                                                             'bulletin': 'DoT Order on Bulk-SIM '
                                                                         'Deactivation Modules',
                                                             'tag': '#SIMSwapFraud'}}},
 'Meghalaya': {'cell_name': 'Meghalaya Cyber Crime Investigation Cell',
               'portal': 'https://megpolice.gov.in',
               'threat_matrix': {'Lottery & Scratch Card Phishing via Instant Messaging': {'severity': 'MEDIUM',
                                                                                           'trend': '➡️ '
                                                                                                    'Stable',
                                                                                           'bulletin': 'National '
                                                                                                       'Cyber '
                                                                                                       'Crime '
                                                                                                       'Portal '
                                                                                                       'Threat '
                                                                                                       'Awareness '
                                                                                                       'Matrix'},
                                 'UPI Collect-Request Reversal': {'severity': 'MEDIUM',
                                                                  'trend': '📈 Upward Spike',
                                                                  'bulletin': 'NCRP Operative '
                                                                              'Protocol on '
                                                                              'Immediate UPI '
                                                                              'Transaction Halts',
                                                                  'tag': '#UPICollectScam'},
                                 'Malicious Loan App Extortion': {'severity': 'HIGH',
                                                                  'trend': '📈 Upward Spike',
                                                                  'bulletin': 'MHA Guidelines on '
                                                                              'Extortionate '
                                                                              'Lending Channels',
                                                                  'tag': '#LoanAppHarassment'}}},
 'Mizoram': {'cell_name': 'Mizoram State Cyber Crime Bureau',
             'portal': 'https://mizorampolice.gov.in',
             'threat_matrix': {'Malicious E-Commerce Clones & Spoofed Gateways': {'severity': 'MEDIUM',
                                                                                  'trend': '➡️ '
                                                                                           'Stable',
                                                                                  'bulletin': 'Consumer '
                                                                                              'Affairs '
                                                                                              'Advisory '
                                                                                              'on '
                                                                                              'Digital '
                                                                                              'Retail '
                                                                                              'Protections'},
                               'Investment Deposit Scam': {'severity': 'MEDIUM',
                                                           'trend': '📈 Upward Spike',
                                                           'bulletin': 'RBI Circular on '
                                                                       'Unregulated Electronic '
                                                                       'Investment Schemes',
                                                           'tag': '#InvestmentScam'},
                               'Malicious Loan App Harassment': {'severity': 'HIGH',
                                                                 'trend': '📈 Upward Spike',
                                                                 'bulletin': 'MHA Guidelines on '
                                                                             'Extortionate '
                                                                             'Lending Channels',
                                                                 'tag': '#LoanAppHarassment'}}},
 'Nagaland': {'cell_name': 'Nagaland Police Cyber Cell HQ Kohima',
              'portal': 'https://nagalandpolice.gov.in',
              'threat_matrix': {'Micro-Lending Ransomware & Device Lockout Vectors': {'severity': 'HIGH',
                                                                                      'trend': '📈 '
                                                                                               'Upward '
                                                                                               'Spike',
                                                                                      'bulletin': 'BNS '
                                                                                                  'Section '
                                                                                                  '318 '
                                                                                                  'Compliance '
                                                                                                  'Framework '
                                                                                                  'for '
                                                                                                  'Cyber '
                                                                                                  'Deception',
                                                                                      'tag': '#LoanAppHarassment'},
                                'Malicious Loan App Extortion': {'severity': 'HIGH',
                                                                 'trend': '➡️ Stable',
                                                                 'bulletin': 'MHA Guidelines on '
                                                                             'Extortionate '
                                                                             'Lending Channels',
                                                                 'tag': '#LoanAppHarassment'},
                                'UPI Phishing Link Distribution': {'severity': 'MEDIUM',
                                                                   'trend': '➡️ Stable',
                                                                   'bulletin': 'NCRP Operative '
                                                                               'Protocol on '
                                                                               'Immediate UPI '
                                                                               'Transaction '
                                                                               'Halts',
                                                                   'tag': '#UPICollectScam'}}},
 'Odisha': {'cell_name': 'Odisha Crime Branch Cyber Cell Cuttack',
            'portal': 'https://crimebranch.odishapolice.gov.in',
            'threat_matrix': {'Chit Fund & High-Yield Crypto Deposit Scams': {'severity': 'CRITICAL',
                                                                              'trend': '📈 Upward '
                                                                                       'Spike',
                                                                              'bulletin': 'RBI '
                                                                                          'Circular '
                                                                                          'on '
                                                                                          'Unregulated '
                                                                                          'Electronic '
                                                                                          'Investment '
                                                                                          'Schemes',
                                                                              'tag': '#InvestmentScam'},
                              'Digital Arrest Coercion Calls': {'severity': 'HIGH',
                                                                'trend': '📈 Upward Spike',
                                                                'bulletin': 'I4C Alert on '
                                                                            'Nation-Wide '
                                                                            "'Digital Arrest' "
                                                                            'Threat Patterns',
                                                                'tag': '#DigitalArrest'},
                              'AePS Biometric Spoofing': {'severity': 'HIGH',
                                                          'trend': '➡️ Stable',
                                                          'bulletin': 'I4C Unified Advisory on '
                                                                      'Biometric Lock Controls',
                                                          'tag': '#AadhaarBiometricSpoofing'}}},
 'Punjab': {'cell_name': 'Punjab Bureau of Investigation Cyber Crime Unit',
            'portal': 'https://punjabpolice.gov.in',
            'threat_matrix': {'Overseas Job Visa & Immigration Processing Fraud': {'severity': 'HIGH',
                                                                                   'trend': '📈 '
                                                                                            'Upward '
                                                                                            'Spike',
                                                                                   'bulletin': 'Ministry '
                                                                                               'of '
                                                                                               'External '
                                                                                               'Affairs '
                                                                                               'Guide '
                                                                                               'on '
                                                                                               'Deceptive '
                                                                                               'Agencies'},
                              'Investment & Trading Platform Fraud': {'severity': 'HIGH',
                                                                      'trend': '➡️ Stable',
                                                                      'bulletin': 'SEBI & I4C '
                                                                                  'Joint Warning '
                                                                                  'on Illegal '
                                                                                  'Trading '
                                                                                  'Platforms',
                                                                      'tag': '#InvestmentScam'},
                              'Digital Arrest Coercion Calls': {'severity': 'MEDIUM',
                                                                'trend': '📈 Upward Spike',
                                                                'bulletin': 'I4C Alert on '
                                                                            'Nation-Wide '
                                                                            "'Digital Arrest' "
                                                                            'Threat Patterns',
                                                                'tag': '#DigitalArrest'}}},
 'Rajasthan': {'cell_name': 'Rajasthan State Cyber Crime Police Station Jaipur',
               'portal': 'https://police.rajasthan.gov.in',
               'threat_matrix': {'Sextortion, Video Call Recording & Escort Service Traps': {'severity': 'CRITICAL',
                                                                                             'trend': '📈 '
                                                                                                      'Upward '
                                                                                                      'Spike',
                                                                                             'bulletin': 'National '
                                                                                                         'Cyber '
                                                                                                         'Security '
                                                                                                         'Strategy '
                                                                                                         'on '
                                                                                                         'Honeypot '
                                                                                                         'Operations'},
                                 'Malicious Loan App Harassment': {'severity': 'HIGH',
                                                                   'trend': '➡️ Stable',
                                                                   'bulletin': 'MHA Guidelines '
                                                                               'on Extortionate '
                                                                               'Lending Channels',
                                                                   'tag': '#LoanAppHarassment'},
                                 'AePS Biometric Cloning': {'severity': 'HIGH',
                                                            'trend': '📈 Upward Spike',
                                                            'bulletin': 'I4C Unified Advisory on '
                                                                        'Biometric Lock Controls',
                                                            'tag': '#AadhaarBiometricSpoofing'}}},
 'Sikkim': {'cell_name': 'Sikkim State CID Cyber Unit',
            'portal': 'https://sikkimpolice.nic.in',
            'threat_matrix': {'Fake Hotel & Himalayan Resort Booking Interceptions': {'severity': 'MEDIUM',
                                                                                      'trend': '➡️ '
                                                                                               'Stable',
                                                                                      'bulletin': 'TRAI '
                                                                                                  'Registry '
                                                                                                  'Directives '
                                                                                                  'for '
                                                                                                  'Commercial '
                                                                                                  'Communications'},
                              'UPI Collect-Request Reversal': {'severity': 'MEDIUM',
                                                               'trend': '📈 Upward Spike',
                                                               'bulletin': 'NCRP Operative '
                                                                           'Protocol on '
                                                                           'Immediate UPI '
                                                                           'Transaction Halts',
                                                               'tag': '#UPICollectScam'},
                              'Investment Deposit Fraud': {'severity': 'MEDIUM',
                                                           'trend': '➡️ Stable',
                                                           'bulletin': 'RBI Circular on '
                                                                       'Unregulated Electronic '
                                                                       'Investment Schemes',
                                                           'tag': '#InvestmentScam'}}},
 'Tamil Nadu': {'cell_name': 'Cyber Crime Wing TN Police HQ Chennai',
                'portal': 'https://tnpolice.gov.in',
                'threat_matrix': {'Matrimonial Identity Spoofing & High-Value Romance Scams': {'severity': 'HIGH',
                                                                                               'trend': '📈 '
                                                                                                        'Upward '
                                                                                                        'Spike',
                                                                                               'bulletin': 'BNSS '
                                                                                                           'Asset '
                                                                                                           'Attachment '
                                                                                                           'Guidelines '
                                                                                                           'for '
                                                                                                           'Cyber '
                                                                                                           'Proceeds'},
                                  'Digital Arrest Coercion Calls': {'severity': 'HIGH',
                                                                    'trend': '📈 Upward Spike',
                                                                    'bulletin': 'I4C Alert on '
                                                                                'Nation-Wide '
                                                                                "'Digital "
                                                                                "Arrest' Threat "
                                                                                'Patterns',
                                                                    'tag': '#DigitalArrest'},
                                  'Investment & Trading App Spoof': {'severity': 'MEDIUM',
                                                                     'trend': '➡️ Stable',
                                                                     'bulletin': 'SEBI & I4C '
                                                                                 'Joint Warning '
                                                                                 'on Illegal '
                                                                                 'Trading '
                                                                                 'Platforms',
                                                                     'tag': '#InvestmentScam'}}},
 'Telangana': {'cell_name': 'Telangana State Cyber Security Bureau (TGCSB) Hyderabad',
               'portal': 'https://tgcsb.telangana.gov.in',
               'threat_matrix': {'Coordinated SIM Swap, UPI Exploits & Toll-Free Route Spoofs': {'severity': 'CRITICAL',
                                                                                                 'trend': '📈 '
                                                                                                          'Upward '
                                                                                                          'Spike',
                                                                                                 'bulletin': 'TGCSB '
                                                                                                             'Operational '
                                                                                                             'Handbook '
                                                                                                             'on '
                                                                                                             'Digital '
                                                                                                             'Evidence '
                                                                                                             'Extraction',
                                                                                                 'tag': '#SIMSwapFraud'},
                                 'UPI Collect-Request Reversal': {'severity': 'HIGH',
                                                                  'trend': '📈 Upward Spike',
                                                                  'bulletin': 'NCRP Operative '
                                                                              'Protocol on '
                                                                              'Immediate UPI '
                                                                              'Transaction Halts',
                                                                  'tag': '#UPICollectScam'},
                                 'Investment & Trading App Fraud': {'severity': 'HIGH',
                                                                    'trend': '➡️ Stable',
                                                                    'bulletin': 'SEBI & I4C '
                                                                                'Joint Warning '
                                                                                'on Illegal '
                                                                                'Trading '
                                                                                'Platforms',
                                                                    'tag': '#InvestmentScam'}}},
 'Tripura': {'cell_name': 'Tripura State Cyber Crime Unit',
             'portal': 'https://tripurapolice.gov.in',
             'threat_matrix': {'Phishing Schemes Targeting Government Employee Portals': {'severity': 'MEDIUM',
                                                                                          'trend': '➡️ '
                                                                                                   'Stable',
                                                                                          'bulletin': 'CERT-In '
                                                                                                      'Advisory '
                                                                                                      'on '
                                                                                                      'Credential '
                                                                                                      'Harvesting '
                                                                                                      'Configurations'},
                               'Malicious Loan App Extortion': {'severity': 'MEDIUM',
                                                                'trend': '📈 Upward Spike',
                                                                'bulletin': 'MHA Guidelines on '
                                                                            'Extortionate '
                                                                            'Lending Channels',
                                                                'tag': '#LoanAppHarassment'},
                               'UPI Phishing Link Distribution': {'severity': 'MEDIUM',
                                                                  'trend': '➡️ Stable',
                                                                  'bulletin': 'NCRP Operative '
                                                                              'Protocol on '
                                                                              'Immediate UPI '
                                                                              'Transaction Halts',
                                                                  'tag': '#UPICollectScam'}}},
 'Uttar Pradesh': {'cell_name': 'UP Cyber Police Headquarter Lucknow',
                   'portal': 'https://cybercrime.gov.in',
                   'threat_matrix': {'Aadhaar Masking Deficits & Cooperative Bank Wire Fraud': {'severity': 'CRITICAL',
                                                                                                'trend': '📈 '
                                                                                                         'Upward '
                                                                                                         'Spike',
                                                                                                'bulletin': 'I4C '
                                                                                                            'Joint '
                                                                                                            'Coordination '
                                                                                                            'Advisory '
                                                                                                            'on '
                                                                                                            'Regional '
                                                                                                            'Hotspot '
                                                                                                            'Tracking',
                                                                                                'tag': '#AadhaarBiometricSpoofing'},
                                     'Digital Arrest Coercion Calls': {'severity': 'CRITICAL',
                                                                       'trend': '📈 Upward Spike',
                                                                       'bulletin': 'I4C Alert on '
                                                                                   'Nation-Wide '
                                                                                   "'Digital "
                                                                                   "Arrest' "
                                                                                   'Threat '
                                                                                   'Patterns',
                                                                       'tag': '#DigitalArrest'},
                                     'SIM-Swap OTP Interception': {'severity': 'HIGH',
                                                                   'trend': '➡️ Stable',
                                                                   'bulletin': 'DoT Order on '
                                                                               'Bulk-SIM '
                                                                               'Deactivation '
                                                                               'Modules',
                                                                   'tag': '#SIMSwapFraud'}}},
 'Uttarakhand': {'cell_name': 'Uttarakhand STF Cyber Crime Cell Dehradun',
                 'portal': 'https://stf.uk.gov.in',
                 'threat_matrix': {'Religious Tourism Helicopter Ride Ticket Spoofs': {'severity': 'HIGH',
                                                                                       'trend': '📈 '
                                                                                                'Upward '
                                                                                                'Spike',
                                                                                       'bulletin': 'Ministry '
                                                                                                   'of '
                                                                                                   'Civil '
                                                                                                   'Aviation '
                                                                                                   'Security '
                                                                                                   'Alert '
                                                                                                   'on '
                                                                                                   'Domain '
                                                                                                   'Cloning'},
                                   'Char Dham Booking Phishing Portals': {'severity': 'HIGH',
                                                                          'trend': '📈 Upward '
                                                                                   'Spike',
                                                                          'bulletin': 'TRAI '
                                                                                      'Directives '
                                                                                      'on '
                                                                                      'Malicious '
                                                                                      'Domain '
                                                                                      'Blacklisting'},
                                   'Digital Arrest Coercion Calls': {'severity': 'MEDIUM',
                                                                     'trend': '➡️ Stable',
                                                                     'bulletin': 'I4C Alert on '
                                                                                 'Nation-Wide '
                                                                                 "'Digital "
                                                                                 "Arrest' Threat "
                                                                                 'Patterns',
                                                                     'tag': '#DigitalArrest'}}},
 'West Bengal': {'cell_name': 'West Bengal CID Cyber Crime Zone Kolkata',
                 'portal': 'https://www.cidwestbengal.gov.in',
                 'threat_matrix': {'Fake Franchise Allocation & Distributorship Traps': {'severity': 'HIGH',
                                                                                         'trend': '📈 '
                                                                                                  'Upward '
                                                                                                  'Spike',
                                                                                         'bulletin': 'Corporate '
                                                                                                     'Affairs '
                                                                                                     'Alert '
                                                                                                     'on '
                                                                                                     'Rogue '
                                                                                                     'Commercial '
                                                                                                     'Directories'},
                                   'Investment & Chit Fund Scam': {'severity': 'HIGH',
                                                                   'trend': '➡️ Stable',
                                                                   'bulletin': 'RBI Circular on '
                                                                               'Unregulated '
                                                                               'Electronic '
                                                                               'Investment '
                                                                               'Schemes',
                                                                   'tag': '#InvestmentScam'},
                                   'Malicious Loan App Harassment': {'severity': 'MEDIUM',
                                                                     'trend': '📈 Upward Spike',
                                                                     'bulletin': 'MHA Guidelines '
                                                                                 'on '
                                                                                 'Extortionate '
                                                                                 'Lending '
                                                                                 'Channels',
                                                                     'tag': '#LoanAppHarassment'}}},
 'Andaman & Nicobar Islands': {'cell_name': 'A&N Cyber Crime Police Station Port Blair',
                               'portal': 'https://police.andaman.gov.in',
                               'threat_matrix': {'Satellite Communication Mimicry & Public Wi-Fi Sniffing': {'severity': 'MEDIUM',
                                                                                                             'trend': '➡️ '
                                                                                                                      'Stable',
                                                                                                             'bulletin': 'DoT '
                                                                                                                         'Directives '
                                                                                                                         'on '
                                                                                                                         'Remote '
                                                                                                                         'Network '
                                                                                                                         'Security '
                                                                                                                         'Architectures'},
                                                 'UPI Phishing Link Distribution': {'severity': 'MEDIUM',
                                                                                    'trend': '📈 '
                                                                                             'Upward '
                                                                                             'Spike',
                                                                                    'bulletin': 'NCRP '
                                                                                                'Operative '
                                                                                                'Protocol '
                                                                                                'on '
                                                                                                'Immediate '
                                                                                                'UPI '
                                                                                                'Transaction '
                                                                                                'Halts',
                                                                                    'tag': '#UPICollectScam'},
                                                 'Fake Tourism Booking Interception': {'severity': 'MEDIUM',
                                                                                       'trend': '➡️ '
                                                                                                'Stable',
                                                                                       'bulletin': 'TRAI '
                                                                                                   'Directives '
                                                                                                   'on '
                                                                                                   'Malicious '
                                                                                                   'Domain '
                                                                                                   'Blacklisting'}}},
 'Chandigarh': {'cell_name': 'Chandigarh Police Cyber Crime Investigation Cell (CCIC)',
                'portal': 'https://chandigarhpolice.gov.in',
                'threat_matrix': {'Online Automobile Sale Escrow & Vehicle Verification Scams': {'severity': 'HIGH',
                                                                                                 'trend': '📈 '
                                                                                                          'Upward '
                                                                                                          'Spike',
                                                                                                 'bulletin': 'NCRP '
                                                                                                             'Immediate '
                                                                                                             'Action '
                                                                                                             'Workflow '
                                                                                                             'on '
                                                                                                             'Stolen '
                                                                                                             'Escrow '
                                                                                                             'Holds',
                                                                                                 'tag': '#UPICollectScam'},
                                  'Digital Arrest Coercion Calls': {'severity': 'HIGH',
                                                                    'trend': '📈 Upward Spike',
                                                                    'bulletin': 'I4C Alert on '
                                                                                'Nation-Wide '
                                                                                "'Digital "
                                                                                "Arrest' Threat "
                                                                                'Patterns',
                                                                    'tag': '#DigitalArrest'},
                                  'Investment & Trading Fraud': {'severity': 'MEDIUM',
                                                                 'trend': '➡️ Stable',
                                                                 'bulletin': 'SEBI & I4C Joint '
                                                                             'Warning on Illegal '
                                                                             'Trading Platforms',
                                                                 'tag': '#InvestmentScam'}}},
 'Dadra and Nagar Haveli and Daman and Diu': {'cell_name': 'DNH & DD Cyber Crime Cell',
                                              'portal': 'https://ddpolice.gov.in',
                                              'threat_matrix': {'Industrial Procurement Internal Phishing Overrides': {'severity': 'MEDIUM',
                                                                                                                       'trend': '➡️ '
                                                                                                                                'Stable',
                                                                                                                       'bulletin': 'CERT-In '
                                                                                                                                   'Ransomware '
                                                                                                                                   'Mitigation '
                                                                                                                                   'Framework '
                                                                                                                                   'for '
                                                                                                                                   'Factories'},
                                                                'Business Email Compromise Wire Fraud': {'severity': 'HIGH',
                                                                                                         'trend': '📈 '
                                                                                                                  'Upward '
                                                                                                                  'Spike',
                                                                                                         'bulletin': 'MeitY '
                                                                                                                     'Statutory '
                                                                                                                     'Advisory '
                                                                                                                     'on '
                                                                                                                     'Synthetic '
                                                                                                                     'Media '
                                                                                                                     'Manipulations',
                                                                                                         'tag': '#DeepfakeFraud'},
                                                                'Malicious Loan App Harassment': {'severity': 'MEDIUM',
                                                                                                  'trend': '➡️ '
                                                                                                           'Stable',
                                                                                                  'bulletin': 'MHA '
                                                                                                              'Guidelines '
                                                                                                              'on '
                                                                                                              'Extortionate '
                                                                                                              'Lending '
                                                                                                              'Channels',
                                                                                                  'tag': '#LoanAppHarassment'}}},
 'Delhi': {'cell_name': 'IFSO (Intelligence Futuristic Strategic Operations) Special Cell',
           'portal': 'https://cybercelldelhi.in',
           'threat_matrix': {'AI Voice Cloning Ransom Demands & Fake Arrest Warrants': {'severity': 'CRITICAL',
                                                                                        'trend': '📈 '
                                                                                                 'Upward '
                                                                                                 'Spike',
                                                                                        'bulletin': 'MeitY '
                                                                                                    'Intermediary '
                                                                                                    'Rules '
                                                                                                    'Enforcement '
                                                                                                    'Directive '
                                                                                                    'on '
                                                                                                    'Deepfakes',
                                                                                        'tag': '#DeepfakeFraud'},
                             'Digital Arrest Coercion Calls': {'severity': 'CRITICAL',
                                                               'trend': '📈 Upward Spike',
                                                               'bulletin': 'I4C Alert on '
                                                                           "Nation-Wide 'Digital "
                                                                           "Arrest' Threat "
                                                                           'Patterns',
                                                               'tag': '#DigitalArrest'},
                             'Customs Courier Parcel Scam': {'severity': 'HIGH',
                                                             'trend': '📈 Upward Spike',
                                                             'bulletin': 'I4C Alert on Courier '
                                                                         'Contraband Extortion',
                                                             'tag': '#FedExCourierScam'}}},
 'Jammu and Kashmir': {'cell_name': 'Cyber Police Station Jammu / Srinagar Nodes',
                       'portal': 'https://jkpolice.gov.in',
                       'threat_matrix': {'VPN-Masked Anonymized Extortion & Spoofed VoIP Routing': {'severity': 'HIGH',
                                                                                                    'trend': '➡️ '
                                                                                                             'Stable',
                                                                                                    'bulletin': 'Home '
                                                                                                                'Ministry '
                                                                                                                'Security '
                                                                                                                'Directives '
                                                                                                                'on '
                                                                                                                'Encrypted '
                                                                                                                'Proxies'},
                                         'SIM-Swap OTP Interception': {'severity': 'HIGH',
                                                                       'trend': '📈 Upward Spike',
                                                                       'bulletin': 'DoT Order on '
                                                                                   'Bulk-SIM '
                                                                                   'Deactivation '
                                                                                   'Modules',
                                                                       'tag': '#SIMSwapFraud'},
                                         'Malicious Loan App Extortion': {'severity': 'MEDIUM',
                                                                          'trend': '➡️ Stable',
                                                                          'bulletin': 'MHA '
                                                                                      'Guidelines '
                                                                                      'on '
                                                                                      'Extortionate '
                                                                                      'Lending '
                                                                                      'Channels',
                                                                          'tag': '#LoanAppHarassment'}}},
 'Ladakh': {'cell_name': 'Ladakh Police Cyber Cell HQ Leh',
            'portal': 'https://police.ladakh.gov.in',
            'threat_matrix': {'Satellite Data Interception Flaws & Identity Impersonation': {'severity': 'MEDIUM',
                                                                                             'trend': '➡️ '
                                                                                                      'Stable',
                                                                                             'bulletin': 'NCIIPC '
                                                                                                         'Guidelines '
                                                                                                         'on '
                                                                                                         'Border '
                                                                                                         'Zone '
                                                                                                         'Digital '
                                                                                                         'Asset '
                                                                                                         'Protections'},
                              'Digital Arrest Coercion Calls': {'severity': 'MEDIUM',
                                                                'trend': '📈 Upward Spike',
                                                                'bulletin': 'I4C Alert on '
                                                                            'Nation-Wide '
                                                                            "'Digital Arrest' "
                                                                            'Threat Patterns',
                                                                'tag': '#DigitalArrest'},
                              'UPI Phishing Link Distribution': {'severity': 'MEDIUM',
                                                                 'trend': '➡️ Stable',
                                                                 'bulletin': 'NCRP Operative '
                                                                             'Protocol on '
                                                                             'Immediate UPI '
                                                                             'Transaction Halts',
                                                                 'tag': '#UPICollectScam'}}},
 'Lakshadweep': {'cell_name': 'Lakshadweep Police Cyber Cell Kavaratti',
                 'portal': 'https://lakshadweep.gov.in',
                 'threat_matrix': {'Maritime Communication Phishing & Rogue Hotspot Deployment': {'severity': 'MEDIUM',
                                                                                                  'trend': '➡️ '
                                                                                                           'Stable',
                                                                                                  'bulletin': 'Indian '
                                                                                                              'Coast '
                                                                                                              'Guard '
                                                                                                              '& '
                                                                                                              'I4C '
                                                                                                              'Joint '
                                                                                                              'Security '
                                                                                                              'Protocol'},
                                   'Fake Tourism Booking Interception': {'severity': 'MEDIUM',
                                                                         'trend': '➡️ Stable',
                                                                         'bulletin': 'TRAI '
                                                                                     'Directives '
                                                                                     'on '
                                                                                     'Malicious '
                                                                                     'Domain '
                                                                                     'Blacklisting'},
                                   'UPI Collect-Request Reversal': {'severity': 'MEDIUM',
                                                                    'trend': '📈 Upward Spike',
                                                                    'bulletin': 'NCRP Operative '
                                                                                'Protocol on '
                                                                                'Immediate UPI '
                                                                                'Transaction '
                                                                                'Halts',
                                                                    'tag': '#UPICollectScam'}}},
 'Puducherry': {'cell_name': 'Puducherry Police Cyber Crime Cell',
                'portal': 'https://police.py.gov.in',
                'threat_matrix': {'French Lineage Document Forgery & Passport Verification Scams': {'severity': 'MEDIUM',
                                                                                                    'trend': '➡️ '
                                                                                                             'Stable',
                                                                                                    'bulletin': 'MEA '
                                                                                                                'Cyber '
                                                                                                                'Advisory '
                                                                                                                'on '
                                                                                                                'Digitally '
                                                                                                                'Sign-Off '
                                                                                                                'Verification '
                                                                                                                'Nodes'},
                                  'Romance & Matrimonial Identity Scam': {'severity': 'HIGH',
                                                                          'trend': '📈 Upward '
                                                                                   'Spike',
                                                                          'bulletin': 'BNSS '
                                                                                      'Asset '
                                                                                      'Attachment '
                                                                                      'Guidelines '
                                                                                      'for Cyber '
                                                                                      'Proceeds'},
                                  'Investment & Trading Fraud': {'severity': 'MEDIUM',
                                                                 'trend': '➡️ Stable',
                                                                 'bulletin': 'SEBI & I4C Joint '
                                                                             'Warning on Illegal '
                                                                             'Trading Platforms',
                                                                 'tag': '#InvestmentScam'}}}}


def all_jurisdictions() -> List[str]:
    """Return every State + UT name, States first then UTs, each alphabetical."""
    states = sorted(n for n in STATE_INTELLIGENCE_METRIC
                    if n not in _UNION_TERRITORIES)
    uts = sorted(n for n in STATE_INTELLIGENCE_METRIC if n in _UNION_TERRITORIES)
    return states + uts


def jurisdiction_kind(name: str) -> str:
    """Classify a jurisdiction as 'Union Territory' or 'State'."""
    return "Union Territory" if name in _UNION_TERRITORIES else "State"


def get_state_intel(name: str) -> Optional[Dict[str, object]]:
    """Return the intelligence record (cell/portal/threat_matrix) for a State/UT."""
    return STATE_INTELLIGENCE_METRIC.get(name)


# --------------------------------------------------------------------------- #
# 2. Threat-mechanism tag taxonomy (cross-referencing matrix).               #
# --------------------------------------------------------------------------- #

# Victim-Triage incident categories the dashboard tags map onto.
TRIAGE_CATEGORIES: Tuple[str, str, str] = (
    "Social & Behavioral Exploitation",
    "Critical Infrastructure",
    "Financial Cyber Fraud",
)


@dataclass(frozen=True)
class ThreatTag:
    """One scam-mechanism tag tying advisories, experts and triage together."""

    tag: str            # e.g. "#DigitalArrest"
    label: str
    mechanism: str
    advisory_body: str
    advisory_url: str
    triage_category: str
    provisions: str     # indicative BNS, 2023 / IT Act, 2000 sections


THREAT_TAGS: List[ThreatTag] = [
    ThreatTag(
        "#DigitalArrest", "Digital Arrest Coercion",
        "Fraudsters impersonate CBI/ED/police on video call, allege parcel/AML "
        "cases, and 'detain' the victim on camera until money is transferred.",
        "I4C / MHA", _I4C, "Social & Behavioral Exploitation",
        "BNS §308 (extortion), §319 (personation), §351 (criminal intimidation); "
        "IT Act §66D, §66C"),
    ThreatTag(
        "#FedExCourierScam", "FedEx / Customs Courier Scam",
        "Caller claims a courier in the victim's name contains contraband; a fake "
        "'customs/narcotics officer' extracts payment to avoid arrest.",
        "I4C / MHA", _I4C, "Social & Behavioral Exploitation",
        "BNS §318(4) (cheating), §319, §308; IT Act §66D"),
    ThreatTag(
        "#AadhaarBiometricSpoofing", "AePS Biometric Cloning",
        "Lifted fingerprints / leaked Aadhaar biometrics are replayed through the "
        "Aadhaar-enabled Payment System to silently withdraw from linked accounts.",
        "RBI / UIDAI", _RBI, "Financial Cyber Fraud",
        "BNS §318(4), §336 (forgery); IT Act §66C (identity theft), §66D, §43"),
    ThreatTag(
        "#SIMSwapFraud", "SIM-Swap / OTP Interception",
        "The victim's MSISDN is fraudulently re-provisioned onto an attacker SIM "
        "so banking OTPs are intercepted and accounts drained.",
        "TRAI / Sanchar Saathi", _SANCHAR, "Critical Infrastructure",
        "BNS §319, §318(4); IT Act §66C, §66D"),
    ThreatTag(
        "#UPICollectScam", "UPI Collect-Request Reversal",
        "A 'buyer' sends a UPI collect (pull) request disguised as a payment; "
        "approving it debits the victim instead of crediting them.",
        "RBI / NPCI", _RBI, "Financial Cyber Fraud",
        "BNS §318(4); IT Act §66D"),
    ThreatTag(
        "#InvestmentScam", "Fake Trading / Investment Syndicate",
        "Slick 'stock advisory' portals show fabricated gains and block "
        "withdrawals, funnelling deposits through mule and mirror infrastructure.",
        "RBI / SEBI", _RBI, "Financial Cyber Fraud",
        "BNS §318(4), §111 (organised crime); IT Act §66D; PMLA referral"),
    ThreatTag(
        "#LoanAppHarassment", "Predatory Loan-App Extortion",
        "Sideloaded loan apps harvest contacts and gallery, then extort victims "
        "with morphed images and mass-contact shaming.",
        "CERT-In", _CERTIN, "Social & Behavioral Exploitation",
        "BNS §308, §351, §78 (stalking); IT Act §66E, §67, §43"),
    ThreatTag(
        "#DeepfakeFraud", "Deepfake Voice / Video Fraud",
        "AI-cloned voices or faces of executives/relatives authorise urgent "
        "transfers or fabricate emergencies to coerce payment.",
        "CERT-In", _CERTIN, "Social & Behavioral Exploitation",
        "BNS §319 (personation), §318(4), §336/§340 (forgery); IT Act §66C, §66D, §66E"),
]

_TAG_INDEX: Dict[str, ThreatTag] = {t.tag: t for t in THREAT_TAGS}


def list_tags() -> List[str]:
    """Return the ordered list of tag tokens."""
    return [t.tag for t in THREAT_TAGS]


def get_tag(tag: str) -> Optional[ThreatTag]:
    """Return a ThreatTag by token, or None."""
    return _TAG_INDEX.get(tag)


def triage_category_for_tag(tag: Optional[str]) -> Optional[str]:
    """Map an active tag to its Victim-Triage incident category."""
    meta = _TAG_INDEX.get(tag or "")
    return meta.triage_category if meta else None


# --------------------------------------------------------------------------- #
# 3. Curated expert & enforcement social-signal feed.                        #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExpertSignal:
    """One curated awareness post from a cyber expert or enforcement handle."""

    author: str
    credentials: str
    handle: str
    published: str           # ISO date
    summary: str
    tags: Tuple[str, ...] = field(default_factory=tuple)
    poster_note: str = ""    # caption for warning-poster art, when applicable


EXPERT_SIGNALS: List[ExpertSignal] = [
    ExpertSignal(
        "Amit Dubey", "Cyber-crime investigator & national-security expert",
        "@theamitdubey", "2026-06-12",
        "Walkthrough of a live 'digital arrest' call: how the fake CBI officer "
        "keeps the victim on video, fabricates an arrest warrant on screen, and "
        "engineers urgency. Never stay on a coerced video call — disconnect and "
        "dial 1930.",
        ("#DigitalArrest", "#FedExCourierScam"),
        "Poster: 'No agency arrests you over a video call.'"),
    ExpertSignal(
        "Dr. Rakshit Tandon", "Cyber-safety evangelist, advisor to police academies",
        "@rakshittandon", "2026-06-09",
        "Vector breakdown of SIM-swap fraud: the 'no network at midnight' warning "
        "sign, why you should never share the porting OTP, and how to lock SIM "
        "re-issue with your operator. OTP interception is the whole game.",
        ("#SIMSwapFraud", "#AadhaarBiometricSpoofing"),
        "Poster: 'Lost network suddenly? Call your operator before your bank.'"),
    ExpertSignal(
        "Nipun Jaswal", "Cyber-security researcher & author",
        "@nipunjaswal", "2026-06-05",
        "Technical teardown of a deepfake CEO-voice wire-fraud attempt — the "
        "tell-tale missing room-tone and synthesiser encoder tags. Verify "
        "out-of-band on a known number before any urgent transfer.",
        ("#DeepfakeFraud", "#InvestmentScam"),
        "Poster: 'Urgent + voice-only + new account = stop and verify.'"),
    ExpertSignal(
        "Maharashtra Cyber", "Official cyber-crime wing, Maharashtra Police",
        "@MahaCyber1", "2026-06-11",
        "Public advisory: surge in FedEx/customs 'parcel with contraband' calls "
        "across Mumbai & Pune. No courier or customs officer demands payment to "
        "release a parcel. Report on 1930 / cybercrime.gov.in.",
        ("#FedExCourierScam", "#DigitalArrest"),
        "Poster: 'Customs never calls to collect money.'"),
    ExpertSignal(
        "Delhi Police IFSO", "Special Cell — Intelligence Fusion & Strategic Operations",
        "@DCP_IFSO", "2026-06-08",
        "Alert on predatory loan apps harvesting contacts and gallery to extort "
        "with morphed photos. Uninstall, preserve screenshots, and file at "
        "cybercrime.gov.in — do not pay the shaming demand.",
        ("#LoanAppHarassment",),
        "Poster: 'A loan app cannot threaten you. Report it.'"),
    ExpertSignal(
        "Telangana Cyber Security Bureau", "TGCSB — Government of Telangana",
        "@TGCSBOfficial", "2026-06-10",
        "Investor warning: fake trading apps showing fake profits then freezing "
        "withdrawals. Verify SEBI registration; deposits routed to mule accounts "
        "are recoverable only if reported within the golden hour on 1930.",
        ("#InvestmentScam", "#UPICollectScam"),
        "Poster: 'If you can't withdraw, it's a scam.'"),
    ExpertSignal(
        "RBI Kehta Hai", "Reserve Bank of India — public awareness",
        "@RBIKehtaHai", "2026-06-07",
        "Reminder: a UPI 'collect request' asks you to PAY, not receive. You never "
        "enter a PIN to RECEIVE money. Decline unknown collect requests and report "
        "AePS debits you did not authorise to your bank immediately.",
        ("#UPICollectScam", "#AadhaarBiometricSpoofing"),
        "Poster: 'Enter PIN only to PAY, never to receive.'"),
]


def signals_for_tag(tag: Optional[str]) -> List[ExpertSignal]:
    """Return expert signals matching a tag (all signals when tag is None)."""
    if not tag:
        return list(EXPERT_SIGNALS)
    return [s for s in EXPERT_SIGNALS if tag in s.tags]


def offline_advisories(tag: Optional[str] = None) -> List[Dict[str, str]]:
    """Static baseline advisory cards (no LLM, no network) for the offline fallback.

    Derived deterministically from the tag taxonomy so the advisory panel always
    populates — scoped to the active tag when set, else the leading vectors.
    """
    chosen: List[ThreatTag] = (
        [t for t in (get_tag(tag),) if t is not None] or THREAT_TAGS[:4]
        if tag else THREAT_TAGS[:4])
    return [{"title": f"{t.advisory_body} — {t.label}",
             "description": t.mechanism,
             "url": t.advisory_url} for t in chosen]
