// Pins for the browser prover: the same programs and keys the Mac engine pins (long3 in backend/integrations/noir/worker.mjs;
// a web test keeps them equal), and the proving points this site serves (the first 2^19 or 2^20 of the setup the Mac
// app downloads, backend/scripts/upload-engine.mjs). `log`: each program's proving size, 2^log, which needs 2^log points.
export const PROGRAMS = {
  chunk1024: { bytecode: '7fb97a2452c2d421f3728f891ce981e3da41f4b7f1ced019acf4c0549c0a4300', vk: '8d8a3bae78664b1b3883b94a1e361d56ee573b7102acc5c18bfd6e721490396b', log: 19 },
  final1024: { bytecode: '0ef8d2d4be19b51eb1727484703837e59d229cea631177b5b4b100cd8a1f3a44', vk: 'c9ce374434fdda60af5c436336410bacc83bdadfaef034ac33432d82a1b3cc28', log: 19 },
  chunk4096: { bytecode: 'a1508af5bebc2f671a49aed30e85866c8de7748c7849cb3247d32c822cf807be', vk: 'a73280bcdb84a952e6ca84bc7bcf264dcaea0ee480b3dde00933d7d123782894', log: 19 },
  final4096: { bytecode: '6a50011e511032c23d70186cb437b70c353fd79aabb89d264dae1635e7764abc', vk: '75414e8be776c623d3eca1177fa1ba2af5f094cd6605427826e0af8c1e5ee95f', log: 19 },
  chunk10000: { bytecode: 'afc3a541737fdc7a0e2c13ef20ec689fce67ced65d3feb9c05be2935d5c08ca4', vk: 'fd0f825f50bfc0312b617bc02141c73a2691df7f444eee5ddd78b219cd3d0ba0', log: 20 },
  final10000: { bytecode: '21da3a3c460175280b96937a3c9e6851725dceee711a90af1d511ac9be7aeb78', vk: '842cdcaebc3c382f4c4f4b478cf08a8505be2a54ebe0e789270cf033aa013ce8', log: 20 },
};
export const POINTS = { 19: '1d03ebeb73e1a6d426e44a2ccc88b04125ca185ab9d1679817380502a723fa80', 20: 'f767d001dd244d42bb3863f0edc7644356ba33c662fe4fe6fb98793f8b918bd4', g2: '01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f' };
