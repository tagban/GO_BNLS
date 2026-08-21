// Package protocol defines the BNLS wire protocol: opcodes and frame
// (de)serialization. Opcode numbers and field layouts are sourced from
// bnetdocs.org's BNLS Packet Guide (https://bnetdocs.org/document/22/bnls-packet-guide)
// and individual packet pages, cross-checked against an independent,
// differently-licensed reference implementation for corroboration — never
// copied or ported from JBLS.
package protocol

// Opcode identifies a BNLS packet type. Values match the byte BNLS uses on
// the wire in both directions.
type Opcode byte

const (
	OpNull                 Opcode = 0x00
	OpCDKey                Opcode = 0x01 // legacy, superseded by OpCDKeyEx
	OpLogonChallenge       Opcode = 0x02
	OpLogonProof           Opcode = 0x03
	OpCreateAccount        Opcode = 0x04
	OpChangeChallenge      Opcode = 0x05
	OpChangeProof          Opcode = 0x06
	OpUpgradeChallenge     Opcode = 0x07 // legacy OLS->NLS account upgrade
	OpUpgradeProof         Opcode = 0x08 // legacy OLS->NLS account upgrade
	OpVersionCheck         Opcode = 0x09 // legacy, superseded by OpVersionCheckEx / OpVersionCheckEx2
	OpConfirmLogon         Opcode = 0x0A
	OpHashData             Opcode = 0x0B // legacy OLS-era password hashing
	OpCDKeyEx              Opcode = 0x0C
	OpChooseNLSRevision    Opcode = 0x0D
	OpAuthorize            Opcode = 0x0E // bnetdocs marks this defunct; still answered for backward compatibility
	OpAuthorizeProof       Opcode = 0x0F // bnetdocs marks this defunct; still answered for backward compatibility
	OpRequestVersionByte   Opcode = 0x10
	OpVerifyServer         Opcode = 0x11 // server-role: for a Battle.net-compatible chat/realm server, not a bot client
	OpReserveServerSlots   Opcode = 0x12 // server-role
	OpServerLogonChallenge Opcode = 0x13 // server-role
	OpServerLogonProof     Opcode = 0x14 // server-role
	OpVersionCheckEx       Opcode = 0x18 // legacy, superseded by OpVersionCheckEx2
	OpVersionCheckEx2      Opcode = 0x1A
	OpWarden               Opcode = 0x7D // official Battle.net anti-cheat proxying — explicitly out of scope, see README
	OpIPBan                Opcode = 0xFF // unofficial, not part of the core bnetdocs spec
)

// String returns the opcode's canonical BNLS_* name for logging.
func (o Opcode) String() string {
	switch o {
	case OpNull:
		return "BNLS_NULL"
	case OpCDKey:
		return "BNLS_CDKEY"
	case OpLogonChallenge:
		return "BNLS_LOGONCHALLENGE"
	case OpLogonProof:
		return "BNLS_LOGONPROOF"
	case OpCreateAccount:
		return "BNLS_CREATEACCOUNT"
	case OpChangeChallenge:
		return "BNLS_CHANGECHALLENGE"
	case OpChangeProof:
		return "BNLS_CHANGEPROOF"
	case OpUpgradeChallenge:
		return "BNLS_UPGRADECHALLENGE"
	case OpUpgradeProof:
		return "BNLS_UPGRADEPROOF"
	case OpVersionCheck:
		return "BNLS_VERSIONCHECK"
	case OpConfirmLogon:
		return "BNLS_CONFIRMLOGON"
	case OpHashData:
		return "BNLS_HASHDATA"
	case OpCDKeyEx:
		return "BNLS_CDKEY_EX"
	case OpChooseNLSRevision:
		return "BNLS_CHOOSENLSREVISION"
	case OpAuthorize:
		return "BNLS_AUTHORIZE"
	case OpAuthorizeProof:
		return "BNLS_AUTHORIZEPROOF"
	case OpRequestVersionByte:
		return "BNLS_REQUESTVERSIONBYTE"
	case OpVerifyServer:
		return "BNLS_VERIFYSERVER"
	case OpReserveServerSlots:
		return "BNLS_RESERVESERVERSLOTS"
	case OpServerLogonChallenge:
		return "BNLS_SERVERLOGONCHALLENGE"
	case OpServerLogonProof:
		return "BNLS_SERVERLOGONPROOF"
	case OpVersionCheckEx:
		return "BNLS_VERSIONCHECKEX"
	case OpVersionCheckEx2:
		return "BNLS_VERSIONCHECKEX2"
	case OpWarden:
		return "BNLS_WARDEN"
	case OpIPBan:
		return "BNLS_IPBAN"
	default:
		return "BNLS_UNKNOWN"
	}
}
