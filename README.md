# esia

```Golang
Esia openId

esiaOpenId := &esia.OpenId{  
      Config: esia.ConfigOpenId{  
              MnemonicsSystem:"000000",  
              RedirectUrl:"https://site/esia",  
              PortalUrl:"https://esia-portal1.test.gosuslugi.ru/",  
              //PortalUrl:"https://esia.gosuslugi.ru/",  
              PrivateKeyPath:"/path/to/esia_auth.key",  
              PrivateKeyPassword:"",  
              CertPath:"/path/to/esia_auth.pem",  
              TmpPath:"/path/to/tmp",  
              Scope:"fullname id_doc",  
              CodeUrl :"aas/oauth2/ac",  
              TokenUrl :"aas/oauth2/te",  
      },  
}

//Get auth url
url, _ := esiaOpenId.GetUrl()

//Get persone info
var person esia.EsiaPerson
esiaOpenId.GetInfoByPath("", &person)

//Get docs info
var docs esia.EsiaDocs
esiaOpenId.GetInfoByPath("/docs/" + fmt.Sprint(person.RIdDoc), &docs)

```
