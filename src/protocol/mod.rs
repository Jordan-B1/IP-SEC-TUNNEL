pub mod server;
pub mod client;
mod shared;

/*

C -Hello-> S
C <-Hello- S
C -PubKey-> S
C <CryptedPubKey- S
C -CryptedOk> S
C <Ok/KO- S


C -Crypted> S
C <Crypted- S
C -Crypted> S

*/