source /home/vvc/Desktop/LabSec/codes/acme-pqc/tests/scripts/config.sh
NUMBER_OF_CERTS=1

echo -e "Run Pebble!\n"
read -p "Is Pebble already running ? (y/n) " PEBBLE_RUNNING

if [ "$PEBBLE_RUNNING" == "n" ]; then
    exit
fi

for (( i=1; i<=$NUMBER_OF_CERTS; i++ ))
do
        rm -rf ${LEGO_DIR}/.lego/*
        echo -e "\n\nOrdering LEGO to issue a classical certificate (iteration ${i})\n"

        go run cmd/lego/main.go \
        -s https://127.0.0.1:14000/dir \
        -d teste \
        -m teste-newchallenge@teste.com  \
        --http.port ":5002" \
        --http \
        -a \
        -k ec256 \
        --certalgo P256 \
        --pqtls \
        --kex Kyber512 \
        --timingcsv ${WRAPPED_CERT_TESTS_DIR}/measurements/lego_issuance_time.csv \
        run

#echo -e "\n\nDownloading Root CA and trusting it for TLS connections..."
#wget --no-check-certificate --quiet https://teste:15000/roots/0
#sudo mv 0 /usr/local/share/ca-certificates/0.crt

#echo -e "\n\nTrusting (overwriting) new issuer teste.issuer.crt"
#sudo cp /home/aagiron/PHD_MAIN_QUEST/PQCACME/modificaciones/go-lego/.lego/certificates/acmenewcert/teste.issuer.crt /usr/local/share/ca-certificates/teste.issuer.crt
#sudo update-ca-certificates

        echo -e "\n\nOrdering LEGO to issue a post-quantum certificate using the NEW Challenge (PQ-Transition Challenge)\n"

        go run cmd/lego/main.go \
        -s https://127.0.0.1:14000/dir \
        -d teste \
        -m teste-newchallenge1@teste.com \
        --http.port ":5002" \
        --http \
        -a \
        --newchallenge \
        --kex Kyber512 \
        -k Dilithium2 \
        --certalgo Dilithium2 \
        --pqtls \
        --timingcsv ${WRAPPED_CERT_TESTS_DIR}/measurements/lego_issuance_time.csv \
        run
#--pqtls \

done
                                         