package protocol

// ProductByte is BNLS's own per-product byte identifier, as documented in
// bnetdocs.org/document/44/bnls-product-codes — distinct from BNCS's
// 4-character wire codes (e.g. "PX3W") used in SID_AUTH_INFO; this is the
// value BNLS_REQUESTVERSIONBYTE and BNLS_VERSIONCHECKEX2 carry on the wire.
type ProductByte byte

const (
	ProductStarCraft            ProductByte = 0x01 // STAR
	ProductStarCraftBroodWar    ProductByte = 0x02 // SEXP
	ProductWarcraft2BNE         ProductByte = 0x03 // W2BN
	ProductDiabloII             ProductByte = 0x04 // D2DV
	ProductDiabloIILoD          ProductByte = 0x05 // D2XP
	ProductStarCraftJapanese    ProductByte = 0x06 // JSTR
	ProductWarcraft3            ProductByte = 0x07 // WAR3
	ProductWarcraft3TFT         ProductByte = 0x08 // W3XP
	ProductDiabloRetail         ProductByte = 0x09 // DRTL
	ProductDiabloShareware      ProductByte = 0x0A // DSHR
	ProductStarCraftShareware   ProductByte = 0x0B // SSHR
	ProductWarcraft3Demo        ProductByte = 0x0C // no short code documented
)

// productNames maps each documented product byte to its short BNLS product
// name (matching bnetdocs's own naming), used as the key into a profile
// catalog.
var productNames = map[ProductByte]string{
	ProductStarCraft:          "STAR",
	ProductStarCraftBroodWar:  "SEXP",
	ProductWarcraft2BNE:       "W2BN",
	ProductDiabloII:           "D2DV",
	ProductDiabloIILoD:        "D2XP",
	ProductStarCraftJapanese:  "JSTR",
	ProductWarcraft3:          "WAR3",
	ProductWarcraft3TFT:       "W3XP",
	ProductDiabloRetail:       "DRTL",
	ProductDiabloShareware:    "DSHR",
	ProductStarCraftShareware: "SSHR",
	ProductWarcraft3Demo:      "WAR3DEMO",
}

var productBytesByName = func() map[string]ProductByte {
	m := make(map[string]ProductByte, len(productNames))
	for b, name := range productNames {
		m[name] = b
	}
	return m
}()

// ProductName returns the short BNLS product name for a product byte, and
// whether it's a recognized/documented one.
func ProductName(b ProductByte) (string, bool) {
	name, ok := productNames[b]
	return name, ok
}

// ProductByteForName returns the product byte for a short BNLS product
// name, and whether it's recognized.
func ProductByteForName(name string) (ProductByte, bool) {
	b, ok := productBytesByName[name]
	return b, ok
}

// RequiresExpansionCdKey reports whether a product needs two CD-keys (base
// + expansion) via BNLS_CDKEY_EX, rather than a single key via BNLS_CDKEY.
func RequiresExpansionCdKey(name string) bool {
	return name == "D2XP" || name == "W3XP"
}
