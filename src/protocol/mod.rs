pub mod client;
pub mod server;
mod shared;

/*

C -Hello-> S
C <-Hello- S
C -PubKey-> S
C <CryptedPubKey- S
C -CryptedMasterPassword> S
C <Ok/KO- S


C -Crypted> S
C <Crypted- S
C -Crypted> S

*/
