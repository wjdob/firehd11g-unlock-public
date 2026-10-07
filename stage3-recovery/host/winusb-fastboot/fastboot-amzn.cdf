; Catalog Definition File for fastboot-amzn.inf.
;
; Inf2Cat.exe is not installed on this host, but it is only a wrapper around
; makecat.exe, which IS available in the Windows Kits:
;
;   "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\makecat.exe"
;
; Build + sign the catalog with:
;
;   makecat -v fastboot-amzn.cdf
;   signtool sign /fd sha256 /sha1 <thumbprint> fastboot-amzn.cat
;
; The signing certificate must then be trusted (LocalMachine\Root +
; LocalMachine\TrustedPublisher) before `pnputil /add-driver` will accept the
; package. See README.md in this folder.

[CatalogHeader]
Name=fastboot-amzn.cat
ResultDir=.
PublicVersion=0x0000001
EncodingType=0x00010001
CATATTR1=0x10010001:OSAttr:2:10.0

[CatalogFiles]
<hash>fastboot-amzn.inf=fastboot-amzn.inf
