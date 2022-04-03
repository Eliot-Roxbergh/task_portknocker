#!/bin/bash -u
# Generate a root CA and then two end-entity certificates signed by this CA
# Output: X.pem X.key X_chain.pem

setup() {
    # delete old artifacts
    rm ./*.crt ./*.key ./*.pem ./*.csr conf/ -r &> /dev/null

    # create required files
    mkdir conf
    echo "" > conf/index.txt
    echo "" > conf/serial
}

create_keys() {
    for name in "$entity_1" "$entity_2" "$signing_CA"; do
        key="${name}.key"
        if [ ! -f "$key" ]; then
            echo "Generating key $key"
            openssl genrsa -out "$key" 2048 || exit 1
        else
            echo "Key exists $key"
        fi
    done
    echo
}

create_signing_CA() {
    CA_cert="$signing_CA.pem"
    CA_key="$signing_CA.key"
    if [ ! -f "$CA_cert" ]; then
        openssl req -x509 -new -subj "/CN=$name/" -key "$CA_key" -nodes -out "$CA_cert" -nodes || exit 1
    else
        echo "CA cert exists $CA_cert"
    fi
    echo
}

create_end_entity_cert() {
    cert="${name}.pem"
    csr="${name}_myreq.pem"
    echo "Creating cert for $name"; echo

    # create CSR
    if [ ! -f "$csr" ]; then
        echo "Creating CSR $csr"
        openssl req -new -subj "/CN=${name}" -key "${name}.key" -nodes -out "$csr" -nodes || exit 1
    else
        echo "CSR exists $csr"
    fi

    # sign CSR with CA
    if [ ! -f "$cert" ]; then
        echo "Creating cert $cert"
        #TODO this should use serial file in conf/ ?
        openssl x509 -req -in "$csr" -CA "$CA_cert" -out "$cert" -CAkey "$CA_key" -keyform PEM -sha256 -CAcreateserial || exit 1
        # or alternatively:
        #openssl ca -cert "$CA_cert" -out "$cert" -keyfile "$CA_key" -keyform PEM -infiles "$csr"

    else
        echo "Cert exists $cert"
    fi
    rm "$csr"
    rm ./*.srl

    # generate certificate chain (must be in order, CA last)
    cat "${name}.pem" "${signing_CA}.pem" > "${name}_chain.pem"
}



# TODO this conf file can be improved
#       e.g. add x509v3 extensions (is CA, ..)
export OPENSSL_CONF=./openssl_certs.conf

entity_1="client"
entity_2="server"
signing_CA="ca"

setup
create_keys

create_signing_CA

name=$entity_1
create_end_entity_cert

name=$entity_2
create_end_entity_cert


