// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;
import {Test} from "forge-std/Test.sol";
import {Poseidon2} from "../src/Poseidon2.sol";
/// Vectors from Huma's reader (backend/integrations/noir/long/reader.mjs poseidon2Permute and deviceRoot; final-text.mjs hash).
contract Poseidon2Test is Test {
    function test_PermuteMatchesReader() public pure {
        uint256 a; uint256 b; uint256 c; uint256 d;
        (a, b, c, d) = Poseidon2.permute(0x0edbed5a86b9bc78633346cdaba26bf1f023435a0aca339a49b9f2f1b45b4ccf, 0x25fb8d3336c214f7488aa352352742ad93944accb9023c86204721a9e5812d97, 0x2cb1648850257235e1244b5df5151c2c98b1349ff6669bb6343bf008c6914786, 0x2dd4685eccc944957551efb2a0aa3249da1216cf705b7a2d23a69bf845110efc);
        assertEq(a, 0x00eb51fff616706a6e490139154feb2f04d693a56f05d81e92cc3868ec50c392); assertEq(b, 0x0ad8e1650e454a1b046d015637dc5db69e596adde32b9fcc71141a1571d2c67d); assertEq(c, 0x05d28929f9fc64fc1975cbea7e17660205973cf2714fe58a70067337adb82a57); assertEq(d, 0x0fa7a8307be96f3d68208a73a0a0e178ad6160b7b6ad9f9163f7609a5bc673d5);
        (a, b, c, d) = Poseidon2.permute(0x2fb57aaeec7cbbaa6281d1eb689ed6fb196f88c44a19a176fc80b4dba9dfb2ba, 0x0ab793cfed2523241bb4620244e0e274de3a4db0a84618b324995caeb9736993, 0x17dcc4db3598f0b38386dbdb1fa7f8143678b89a1e1e573adb453376b0e4efdc, 0x2521dfb91aaa23cdad113a30123e574a7e2a3a194dde453263c9dcc797d21e22);
        assertEq(a, 0x2b3dac8beb00091d2f776de7a6bb8bac8cad20f91925f49d0127a68581b66278); assertEq(b, 0x02f21aa6bc2a8a6f5e91c57a7692c15bccc382d044575762863512e417f49d90); assertEq(c, 0x25213728d42bcb63d3d3cddf5695731b725618b8dd014b7429cda0704ad68954); assertEq(d, 0x186523c0dcc1651e1911fcb436f8d00ff7a33caf067efb1e6eaed67f065c3b1d);
        (a, b, c, d) = Poseidon2.permute(0x1b569831d5f28f98e55211d1a4a702155e1980d9ac716e4f425140de381e1709, 0x2b14b47f5b7a3527f47ed80d8153b22bd2f80445c0b84877dcb710c4d37e6a90, 0x04bd78a9fc6056ca3eb531eb48063085c1e04e3957b41eef8ae6671394f1f2c5, 0x062c9e9294524372c1ee2f3bbef556c218cf12095e7375186ff0805e34eb1e05);
        assertEq(a, 0x1ba90337765d3ba6ed918e6ec0588eea4f2e22582ac820aedf5a40cb398fb134); assertEq(b, 0x022cd8d54362a4d2a140ed02e8b98672ddfa06bacf19a96a2619b30a7bc66a89); assertEq(c, 0x1d8b0a4c815955841ca88ad6a60d83354403d053dce39c93ba39041dca1bce01); assertEq(d, 0x2c85d5d144f59bafd49aaf90c2fd8064bf7acd50b8b80138413d567fe223e44e);
        (a, b, c, d) = Poseidon2.permute(0x28699f42c3fe5aba334c935c30c02c2eb1ad6400ae5a475cb216dc1a91fbadf4, 0x07df5dfb5ab1e40c64435d041c743403212a34ec629cb864f65b980ad277fd9f, 0x030f565b5bf03876450de938d015210ce82084fad4fd764d324bb4c25fe4d295, 0x29dddeb88d25d6031d0374156d99bad9faae719e42466edcec0396c8efee6e12);
        assertEq(a, 0x1722cd31a8aab75e630c70837d49380f76fd2b6c6d849b695fdbe52cd5ab831e); assertEq(b, 0x2b71be908f7be129fc2824646233ed31f8544f124624de812721513e0f708e7b); assertEq(c, 0x051fde6f876dad9f3b5e6e3f947b2d8f6e1e3532a68d812d3265cde630ed2502); assertEq(d, 0x1a75709911efbeb22ff7c8efa4ede37b22221ad75109dfaaddf54d03a962f551);
    }
    function test_HashMatchesReaderForEveryLength() public pure {
        uint256[] memory x;
        x = new uint256[](1); x[0] = 0x1663360340a9a49c796370f212a1673c5a710288c47549af0b85e48544d8f569;
        assertEq(Poseidon2.hash(x), 0x209f7acfa3d53338242eacaedaa456c8ec3bf5ae61ef3b62a11958cb6dce1286);
        x = new uint256[](2); x[0] = 0x166b1b4aabcae269f42575760f8a2b7c0c9c1926f6e1d45b9fe440c358e6231b; x[1] = 0x1c70ba7d318f4000425e7ebf088617c5dff29773346390d255d8f4bb8892874f;
        assertEq(Poseidon2.hash(x), 0x190eb6d054bc3755d6d94fa6b04e7386f68d600456033ec2efb514a1fa94ab3d);
        x = new uint256[](3); x[0] = 0x2519d0d3fbc5f7eebd1be93aa025166fc4b8fb5f0d88b56a9e31ef264f03bfa7; x[1] = 0x18790225bff9d465ad9400e847a53a6cdf397587d31ec71e6f4600c3b704c4f2; x[2] = 0x00a09879b34c48836ce350e3a6f2f0d98a80422eb12f6b251beda0cc7b6c365d;
        assertEq(Poseidon2.hash(x), 0x0eaa3e086c54558b26a0d34b6fca41602beaa536b4f38d44a3e83756006bbaa9);
        x = new uint256[](4); x[0] = 0x03cd454069ea91a3dc8af2f175dadc01b01eb16030c8cfc4efe84b6dc3e94481; x[1] = 0x17c7d6494d6ffdd545dd6111578f8b9968ca6a71e9ccbcb133b2aebb1ce34f49; x[2] = 0x0c96e345e715eb43592522ac8affe5bb78901a322efa2b87595f70cf659e85c1; x[3] = 0x10762e3e36f6780fd6ba261e7807bcd1de503cab7e385aa4c32f8b5c827e1625;
        assertEq(Poseidon2.hash(x), 0x04f249e47e5bc2b6fa0b78849645a6655ee08904c55acc17d0475b4590514712);
        x = new uint256[](5); x[0] = 0x112ee99b7bee5aee69f18d0ea2ddec997177d37469fd3cb0a7162deb63b79216; x[1] = 0x2cd8be964a3bc9826004b14660c94d5a3bd3ddb0d732977a48ff3fc7ca1f0218; x[2] = 0x16e0fdeb73530902d76f51ca39cd4d9e6ff12bdada815325b0a55ba6df6e13bc; x[3] = 0x01a1088cad77ba786516ef2c514ecb5fc671a753d4338adaca6a42e547bde03f; x[4] = 0x2d052c72984466ce8494114fd20af40aba55995e9617adf186eeeb723d5b94d3;
        assertEq(Poseidon2.hash(x), 0x285abba31d4d90e5f58be6986f59eee60286db7209543e37b868fc7fd0095926);
        x = new uint256[](6); x[0] = 0x1451fce3ff1817c2d95ae633135f5cdea4da14e1d1c4c046f69a2a684da5bcf1; x[1] = 0x1ada59896ddc097b2987b653772b96853b84227e4a27d67a318c294fffb34149; x[2] = 0x0e988549dd0acc7b36f2c96b018d14ce887ee801296697396fa2050576dbce60; x[3] = 0x1d944b25d026f719d0066364b3bbdb279d599a79093e7ff52ac0141599dbc451; x[4] = 0x1f21c9c0852cbe121aced765ae251870ad78453aa46ea18bdc945da1a545c1f2; x[5] = 0x2e607942bec6bd4f2bc43058e444bda2ad11e74d7be37ff94562ebe6581c313b;
        assertEq(Poseidon2.hash(x), 0x2942af5be7b28b48d8aecc08183ca271a539aeb493650f5306c5e1efaf48ba9b);
        x = new uint256[](7); x[0] = 0x17a354ff71a0b548e78b801c09b0062c7fe5ba10dd9b37efb85c0aaf04cef81d; x[1] = 0x049d2283ac2a02c2a7615ff407d6a519f4f0f3ce987900d971a3c4cca4c1b86f; x[2] = 0x00ebf6041eb1fa18ceeabf9cb0a4431c77c77d41462e39c1a72beea93068d1ff; x[3] = 0x033338d33633793fa4e832ace01dda9fcc39eb6a634e69b962170b78e4eab401; x[4] = 0x1029195126952edad129f9d86767548e527258900d8c7eeb387817859249868d; x[5] = 0x1e07c789306f51e174304f4a65dccbd692a397177f2be619f28ca75c716ce331; x[6] = 0x1aaf52cb30556b03bf89142f4b0c1184212fe2c16898486c839c4d14b28bc506;
        assertEq(Poseidon2.hash(x), 0x178b907d837b9c6ad8f231ddc7568da63c7b2630fe888b3f0cc3b6e534bbc95b);
    }
    function test_DeviceRootOfTheFixtureKey() public pure {
        // key = 04 || X || Y of test/fixtures/long-case-400 (its page proof's publicKey); halves are 16-byte big-endian.
        uint256[] memory x = new uint256[](5);
        x[0] = 0x48554d410801; x[1] = 0x00000000000000000000000000000000579b69a51daed22ae5a257d106cb39a3; x[2] = 0x0000000000000000000000000000000092207b35c30e7062a3a9ca4a8263a588;
        x[3] = 0x000000000000000000000000000000005c1eb63e25b0fb1f767117b4890dae09; x[4] = 0x00000000000000000000000000000000cbb732d21bb2288ac1f0e404d2b56927;
        assertEq(Poseidon2.hash(x), 0x2248fa739f65413fd50dd7ae4c9b63224dd89ea00c9d9bdd8b4eaa94bbf4c108);
    }
    function test_PermutationGas() public {
        uint256 g = gasleft();
        Poseidon2.permute(1, 2, 3, 4);
        emit log_named_uint("gas per permutation", g - gasleft());
    }
}
