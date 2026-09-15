package tokens_test

import (
	"encoding/hex"
	"testing"

	"github.com/adem-wg/adem-proto/pkg/tokens"
)

func TestCalcKID(t *testing.T) {
	tests := []struct {
		kid  string
		cbor []byte
	}{
		{
			kid:  "o3k3mlnzj4snotpsi6eall7g2jvveiyjvq5twu7mrbrgqt62ha3q",
			cbor: mustHex("a50102033823200321584200689b393bc5979ca9f9b42493aba9c9589e2796da5393f929727e96987f3177193eab9982daf0b9227e1fe4872c07b8112ffad50ec992ebe70070dbffbd16533b4d22584200b65872bf85e5d4d7a0b2ce76f6ea0ec92e277848858ec3314b544bbc36dc6b11c99e2aeea61d2ba92e347a1f9ec09556c1ecf5712f6e70bac016a848977a700a9b"),
		},
		{
			kid:  "mftrnsir7sg3nandydalngkt6pni7jmtf3j4hvo6tn7xtfblo4ia",
			cbor: mustHex("a501020338232003215842001139ce7bcfb0fa6d4b4979734b5d6adfaccc58ee705e23b7ab5bcac126d7183de2d45d7408d13e4e8ac2dc7604ac0c9d2faa3a34d17fffcaac164d482ac0078ea8225842017b477b537ae66c351c3196e9ab8b2ea3b48b765c866133dc1a2161535f9bdbe96a6d3ecca43c50ab0080180dd94bbfcc33ef34b51a9b70ecbd39355d5f2ebdc497"),
		},
		{
			kid:  "ybve75quvxoli67fdf3h5zj2bu2br3qh7xmhdme65c6yzgblmuxa",
			cbor: mustHex("a5010203382320032158420046981f89cc1b7c91f7dc7f5702d688f88345f791cf52aefa738da3d5d8497cc53d7e390ec51609d81e5e84313cffe14f3e134161aeb46b5ef375f00fc36ef9064b225842013425ecfbdf97c7b0699a5d29dd88211fd64338634b46a6234fcbdeaea51e16a79d8c503148b28599f5a68d0cea3464295eab9316988c9ee5bee3f3dbaad44b66d7"),
		},
		{
			kid:  "ibolyegnqspxqceqakjwmhxhhg43y7jsmp5q3ypuzcdguudgh24a",
			cbor: mustHex("a50102033823200321584201507375edcec8571092d70831899945514e9bb2ef9c81565a8b4c6dc708a08f07b9aa911e709b83bd41fae3b2cadbbf87e18da09a3d5245ea25b22e3bf9a828f52822584200b93028c730d5b1d221319d238b21ca36fe197c7f1d09b79c065912701a840c5dc4e505b5bf8f6473c10b40a183e71fc9f1e9458c4c4104b0aa683cec5549d4fef4"),
		},
		{
			kid:  "cncejqz5me4jbuzvdx5i74i6344fo65g4ysluwe56mmfpq5gn4cq",
			cbor: mustHex("a5010203382320032158420093d3f8d06f65e4f29715506b217fff16625837d0a721cc3e6c0fb96bfe18cb9b4fc6be9ef2220c1dea9ba3c01c701964c501be05072b806780bb63f11e69ae49e72258420087c819807f20e469d4beab95c0601aecccd0af5cbc8d723698aeccc6fe5d99ae85a1b4409f11838d3d576dc11b3acdcc2361dffd5e9068ac81cbfcd4f236ed63ce"),
		},
	}

	for _, test := range tests {
		pk, err := tokens.DecodePublicCOSEKey(test.cbor)
		if err != nil {
			t.Fatal(err)
		}
		kid, err := tokens.CalcKID(pk)
		if err != nil {
			t.Fatal(err)
		}
		if kid != test.kid {
			t.Fatalf("kid %s, want %s", kid, test.kid)
		}
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
