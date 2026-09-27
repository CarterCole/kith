# Can I read a US passport and verify the signature?

**Yes.** Every US passport issued since 2007 has an NFC chip whose data is digitally
signed by the State Department. A phone can read the chip and verify that signature
offline. There are three important caveats:
- **a browser can't read the chip**;
- the signature proves the *data* is genuine, not that the person holding the phone is
  the passport holder;
- US passports probably can't prove the chip isn't a clone.

## How the chip works (ICAO Doc 9303)

1. **Access control.** You can't read the chip without knowing data printed on the
   passport. With **BAC** (Basic Access Control), the key is derived from the machine
   readable zone (MRZ): the document number, date of birth and expiry date. That is why
   readers first OCR the photo page. **PACE** is the stronger replacement. US passports
   use BAC. PACE support on the newer polycarbonate "Next Generation" passports is
   unconfirmed, so plan for BAC.
2. **Data groups.** DG1 holds the MRZ data (name, nationality, dates). DG2 holds the
   face image. Other groups are optional.
3. **Passive Authentication (PA)** is the signature you asked about:
   - `EF.SOD` contains a hash of every data group, inside a CMS SignedData;
   - it is signed by a **Document Signer Certificate (DSC)**;
   - the DSC is signed by the country's **CSCA** root.
   - To verify: hash the data groups, check the SOD signature with the DSC, check the
     DSC against the US CSCA and its CRL.
   - US signatures are **RSA with SHA-256**. RSA-2048 is reported. ZKPassport's dataset
     lists the "U.S. Department of State MRTD CA" under `sha256WithRSAEncryption`.
4. **Clone detection** comes from Active Authentication (AA: the chip signs a challenge
   with a private key; public key in DG15) or Chip Authentication (CA: key agreement
   with a chip key in DG14). Passive Authentication alone **cannot detect a cloned
   chip**. The available evidence, though thin and dated, suggests US passports don't
   implement AA. Treat US passports as PA-only.

## Where the trust anchors come from

- **ICAO Master List**: publicly downloadable after accepting terms.
  https://www.icao.int/icao-pkd/icao-master-list
- **ICAO PKD** downloads of DSCs and CRLs: https://download.pkd.icao.int/
- **German BSI** CSCA master list:
  https://www.bsi.bund.de/EN/Themen/Oeffentliche-Verwaltung/Elektronische-Identitaeten/Public-Key-Infrastrukturen/CSCA/csca_node.html
  I haven't confirmed that it includes the US CSCA.

## What can read it

| Platform | Can it read an ePassport? |
|----------|---------------------------|
| **Web browser** | **No.** Web NFC is NDEF only; ISO-DEP (what passports speak) is explicitly out of scope, and it only ships on Android Chrome. |
| **iOS app** | Yes. Core NFC `NFCTagReaderSession` with `NFCISO7816Tag`. It needs the NFC entitlement and the passport AID `A0000002471001` in Info.plist. Library: [NFCPassportReader](https://github.com/AndyQ/NFCPassportReader) (BAC, PACE, AA). |
| **Android app** | Yes. `IsoDep`. Library: [JMRTD](https://jmrtd.org) (0.8.1). |
| **Desktop / CLI** | Yes, with a USB PC/SC NFC reader. Rust crates exist but are immature (`emrtd`: BAC + PA only). Python: [pymrtd](https://github.com/ZeroPass/PassID-Server/blob/master/src/pymrtd/README.md), which is not on PyPI. |

## How this fits Kith

A passport is an **attribute source, not a login method**. The flow:

1. A Kith mobile app (or a CLI with a USB reader) reads the chip with BAC, using the
   MRZ from the camera.
2. It verifies Passive Authentication against the CSCA list.
3. It binds the result to the identity. Options, weakest to strongest:
   - **Self-attested**: the device signs `{dg1 hash, SOD}`. Weak: anyone could have
     read that passport.
   - **Face match**: compare DG2 with a liveness selfie. This is what Apple does for
     Digital ID.
   - **Zero-knowledge**: prove "a US passport, CSCA-signed, the holder is over 18, not
     on a sanctions list, and it hashes to this nullifier" without revealing the data.
4. The hub records verified attributes (`nationality`, `age_over_18`, `passport_verified`,
   and a uniqueness `nullifier` for one-person-one-account). They flow into
   `attrs`, so policies can require `principal.passport_verified`, and dynamic groups
   can use them.

**Don't store or forward raw passport data.** A signed DG1 is non-repudiable PII: it
proves your name and birth date to anyone you hand it to. Prefer the ZK approach, which
several projects already ship:

| Project | Status |
|---------|--------|
| [Self](https://self.xyz) (formerly OpenPassport) | Proves age, nationality, uniqueness, and OFAC non-membership from passports and IDs. |
| [ZKPassport](https://github.com/zkpassport/circuits) | Noir circuits, proving on-device. Acquired by Aztec in May 2026 and still open source. |
| [Rarimo / RariMe](https://docs.rarimo.com/zk-passport/) | ZK passport SDK. |
| [World ID passport credential](https://docs.world.org/world-id/credentials/9303) | NFC passport credential, available in the US. |

For Kith, consuming one of these proofs as an attribute source is less work, and more
private, than building the circuits.

## The easier path for web: the Digital Credentials API

Apple Wallet **Digital ID** (launched November 2025) creates an ID from a US passport's
chip plus a selfie and liveness check. Chrome 141 and Safari 26 shipped the W3C
**Digital Credentials API**, which lets a website ask the OS wallet for an ID (ISO
18013-7, mdoc) with user consent. Safari supports only `org-iso-mdoc`. Chrome also
supports OpenID4VP.

Kith's browser client could request an mdoc, verify the issuer signature at the hub, and
record the same attributes, without any NFC code. It is **unconfirmed** whether websites
can request the *passport-derived* Digital ID yet, as opposed to state IDs and driver's
licenses. Apple describes it as "in the future".

## Suggested order of work

1. A Digital Credentials API (mdoc) attribute source in the JS client and hub. It
   reaches the most users with the least code.
2. A Self or ZKPassport proof verifier as a second attribute source (privacy-preserving,
   works for passports today).
3. A native NFC reader (iOS and Android), with PA verification in `kith-core`, for
   offline and CLI use. This is the full "read the chip, verify the sig" path.
