cd ..

go run cmd/lego/main.go \
-s https://127.0.0.1:14000/dir \
-d teste \
-m teste@teste.com \
--http.port ":5002" \
--certpsk 1b1c6e42518211e0abf23d0b78fae2592a44d6542dbe215deaf20ef23dffff95 \
--certlabel ae9102b6d64604f2f7825b8e2f7adb2b49a319e96c0d8f7527e2a8de54050cd0fb31586f2b0cabfd51df5d7a00170573f7acc9941e2a7e634b85a9f7b3d5431fbfd563458eed6f00c340b7b1420fb69352843f468695b0a0598eb02e294875a32bf59c09d322052526dad5fe429018abdf \
--http \
-a \
run