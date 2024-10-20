const getAccessToken = () => {

  const auth = {
  "type": "service_account",
  "project_id": "emdadul-gas-serv---${}",
  "private_key_id": "6e90ef376e5948e439881d1b91cec---${}",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAo---${}JlxvOtuM\nvzwB+CzWclx0ayO9QK1ZMnpCZCIP834fHmjIhstjkmSup4AkgY8ex/gtSBwH1i92\nXRRlRHPNXd8idXKRTTrsvJuGSem3BuN0M9aKJUp0mPNmH/t7FjuaICjJqBJ9E+6U\nY9+sClflsl5oH8i8meH5NPumO9h2ENpx2H+353PcQW3SZgfRAogywGZ3v6aXYlM6\nMbeu2vgA2rK/qe45Jj0zZCzhh+XpSee8wVieOMKGTlS+U9l3wmEEmL+wQyf0GJ5f\npPtSD1d+HUdzgID9mHTgmM0Iprl8K/ouKQDUc6HL5W2FwXlfepybJig5x5HwfWSR\nV4d4LGIhAgMBAAECggEAFW1+gKQ5mk19TtzdOULhaLtL1Nb5f9Zc6/OzquRHrPSH\nsLi1ImrQ3YmcFXBr4HuyrjJViONm69FDS54iRbPWWnkabxTzGw8BbR64IbA4/nyH\nfggUqqmv9oa2o950ceu7jXgfJ/K0xiZnxcwGfMnSn4n/MLgnJVrpx3fbV1O1LrPc\nmJ2ViTxMJHsrUJRx3AnOK9LXvNJey+ktnfxB9kX5wAbyTQkbuBHAcAtKod1EFrVk\nfxRrlbf3ApaqiLbDhR3Z3Zvb7rn6bZUPAnEcbLlBM3RQrt7C867qjq5MqdLsxN+M\nM5kUZc/2j39WVxvi6rKvaDfzxlWKjq/bFNghdYoHJQKBgQDvhnEe9qhKOm/JCdc+\n+zf78Mf4NDxEIKKAGn6/kpeKjt3ocZiEcq2AKqe2u81lAwzpTKdHN+xjFfpmpwhX\nU+61uua3DKtt5DWJENdYjHbyKgXruokPDwk+qQFy39ahnADDqCEanmD5yvzc5Sp9\nhsXoeTLbXL3xuNTlNh3TsfIvxQKBgQDDXAYuxTvzgCMjUky+VuXW5tPd5K1KacE7\nShaNTDCiKv98l3pkYS8SqQeLoEvepEMzliH1q+v3ZBOMi+01logfKhUlmc63+BiT\n4zI0Sru6Mw+U3NBdbsa3m/fn+KCOo84LOdLikw+WK2nOstNgwe+FT5jZeoEHQ7tU\n8JtD+bFSrQKBgHR7fgGf1EGc34X1+i5Pv28PLkA/Ltu2vy/rMp55bKbeSX5j19b5\nafS9Sahs9jrcW+gM9gCFarjZFFfdfQny8FCCXva/+5JKe9p3TTJrxOCJnS2BHmwr\nVMSbLfAueNNI6Xo9BjRKt0Bi/ctyytIWu6INZrUVCe5Gg4ogYir0C6I9AoGABu/C\njHCWY1v+Y2etr+h3+rxxc2SGPqkooklMKbI129w4/ByIzP2iZUA5M1z6tKoSdMd0\n5zs2gq87/naNcqSoqqqc25vtehzGCqI7ix3IMqFTgU6h219ukOBp2gO697WbQEzK\nTx83o3ZhKGSzGrFoJsyfucEeybo+8ZIlgTFheXUCgYAFE9g2EWVL1zF66z6fY/s8\nqYuM5OHU9sn4v9OZTYeNQXE0BLsheqkEOP7y31vcR5Yjij37jOq2niAJVQP8eTuj\nMszpIaKGgwj5FebcADZ3x96/VK110wREbs7uS9OyCyGxdvgAmjufGrewxT94WA7u\nabuoRZwH0WYIdZcjZrfdlw==\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-gdniq@emdadul-gas-servi---${}",
  "client_id": "1146568826306---${}",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-gdniq%40emdadul-ga---${}am.gserviceaccount.com",
  "universe_domain": "googleapis.com",
   "scope":"https://www.googleapis.com/auth/firebase.messaging"
}

  

  const privateKey = auth.private_key;
  const clientEmail = auth.client_email;
  const scopes = auth.scope;  // Specify the required scope(s)

  const jwtHeader = {
    alg: "RS256",
    typ: "JWT"
  };

  const jwtClaimSet = {
    iss: clientEmail,
    scope: scopes,
    aud: "https://oauth2.googleapis.com/token",
    exp: Math.floor(Date.now() / 1000) + 3600,  // Expires in 1 hour
    iat: Math.floor(Date.now() / 1000)
  };

  const base64Encode = obj => Utilities.base64EncodeWebSafe(JSON.stringify(obj)).replace(/=+$/, "");
  
  const unsignedJwt = base64Encode(jwtHeader) + "." + base64Encode(jwtClaimSet);
  const signature = Utilities.computeRsaSha256Signature(unsignedJwt, privateKey);
  const signedJwt = unsignedJwt + "." + Utilities.base64EncodeWebSafe(signature).replace(/=+$/, "");
  
  const tokenUrl = "https://oauth2.googleapis.com/token";
  
  const response = UrlFetchApp.fetch(tokenUrl, {
    method: "post",
    payload: {
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: signedJwt
    }
  });

  const result = JSON.parse(response.getContentText());
  return result.access_token;

}
