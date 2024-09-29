# PlatformSSO


Apple PlatormSSO 

this is just some code for Plaform SSO so people can work it out, works with 
This is jsut as i could not find anything this will hopefully help someone out there with getting this set up 




https://twocanoes.com/psso-technical-deep-dive/ - however needs some changing to how it lables the files, with the wrong name,

convert 
```


// decodedSigningKeyID, err := base64.StdEncoding.DecodeString(request.SignKeyID)

		// if err != nil {

		// 	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		// 	return
		// }
		filename := request.SignKeyID + ".json"
```
