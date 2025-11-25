package tokens_test

import (
	"testing"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestCalcKID(t *testing.T) {
	tests := []struct {
		kid  string
		json []byte
	}{
		{
			kid:  "jhn3xih42qaufdseof7ldv5iwgck5oo725cf63aryl2tr6evxbyq",
			json: []byte(`{"alg":"ES512","crv":"P-521","kty":"EC","x":"AGibOTvFl5yp-bQkk6upyVieJ5baU5P5KXJ-lph_MXcZPquZgtrwuSJ-H-SHLAe4ES_61Q7JkuvnAHDb_70WUztN","y":"ALZYcr-F5dTXoLLOdvbqDskuJ3hIhY7DMUtUS7w23GsRyZ4q7qYdK6kuNHofnsCVVsHs9XEvbnC6wBaoSJd6cAqb"}`),
		},
		{
			kid:  "3oepjm7zfw4vhfgnkji7qtpxzc4pnmtt7kzcxogn5l25ziqp7dka",
			json: []byte(`{"alg":"ES512","crv":"P-521","kty":"EC","x":"ABE5znvPsPptS0l5c0tdat-szFjucF4jt6tbysEm1xg94tRddAjRPk6Kwtx2BKwMnS-qOjTRf__KrBZNSCrAB46o","y":"AXtHe1N65mw1HDGW6auLLqO0i3ZchmEz3BohYVNfm9vpam0-zKQ8UKsAgBgN2Uu_zDPvNLUam3DsvTk1XV8uvcSX"}`),
		},
		{
			kid:  "ws7s5ph5hf65njltup4jmp3zpcr72jzcwmcqx35h6qyhdk6mcjva",
			json: []byte(`{"alg":"ES512","crv":"P-521","kty":"EC","x":"AEaYH4nMG3yR99x_VwLWiPiDRfeRz1Ku-nONo9XYSXzFPX45DsUWCdgeXoQxPP_hTz4TQWGutGte83XwD8Nu-QZL","y":"ATQl7Pvfl8ewaZpdKd2IIR_WQzhjS0amI0_L3q6lHhannYxQMUiyhZn1po0M6jRkKV6rkxaYjJ7lvuPz26rUS2bX"}`),
		},
		{
			kid:  "cots7dtsfu7xd2kfbj4dwcrxo4weatvhls7x5jgmgrkga2ifsbca",
			json: []byte(`{"alg":"ES512","crv":"P-521","kty":"EC","x":"AVBzde3OyFcQktcIMYmZRVFOm7LvnIFWWotMbccIoI8HuaqRHnCbg71B-uOyytu_h-GNoJo9UkXqJbIuO_moKPUo","y":"ALkwKMcw1bHSITGdI4shyjb-GXx_HQm3nAZZEnAahAxdxOUFtb-PZHPBC0Chg-cfyfHpRYxMQQSwqmg87FVJ1P70"}`),
		},
		{
			kid:  "67sl6tpslum3olklx7owqkmvnqmmrf75dxzniuyjk5acyf4il5ua",
			json: []byte(`{"alg":"ES512","crv":"P-521","kty":"EC","x":"AJPT-NBvZeTylxVQayF__xZiWDfQpyHMPmwPuWv-GMubT8a-nvIiDB3qm6PAHHAZZMUBvgUHK4BngLtj8R5prknn","y":"AIfIGYB_IORp1L6rlcBgGuzM0K9cvI1yNpiuzMb-XZmuhaG0QJ8Rg409V23BGzrNzCNh3_1ekGisgcv81PI27WPO"}`),
		},
	}

	for _, test := range tests {
		if pk, err := jwk.ParseKey(test.json); err != nil {
			t.Errorf("couldn't parse key: %s", err)
		} else if _, err := tokens.SetKID(pk, true); err != nil {
			t.Errorf("couldn't set kid: %s", err)
		} else if kid, ok := pk.KeyID(); !ok {
			t.Errorf("kid set but cannot fetch")
		} else if test.kid != kid {
			t.Errorf("pk.kid = %s; want: %s", kid, test.kid)
		}
	}
}
