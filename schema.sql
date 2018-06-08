create table Messages (
    id int auto_increment primary key,
    # RSA ciphertext
    manifest blob(256) not null,
    # RSA Signature + IV + AES ciphertext
    body blob(1296) not null,
    time_uploaded datetime not null
)