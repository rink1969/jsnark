/*******************************************************************************
 * Author: zhiwei ning <rink1969@cryptape.com>
 *******************************************************************************/
package examples.gadgets.hash;

import java.util.Arrays;
import java.math.BigInteger;

import util.Util;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;

public class EaglesongGadget extends Gadget {

    private static final int[] BIT_MATRIX = {1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1,
            0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1,
            0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1,
            0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0,
            1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1,
            1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0,
            1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1,
            0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1,
            0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1,
            0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1,
            0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1,
            1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0,
            0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0,
            0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0,
            1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1};

    private static final int[] COEFFICIENTS = {0, 2, 4,
            0, 13, 22,
            0, 4, 19,
            0, 3, 14,
            0, 27, 31,
            0, 3, 8,
            0, 17, 26,
            0, 3, 12,
            0, 18, 22,
            0, 12, 18,
            0, 4, 7,
            0, 4, 31,
            0, 12, 27,
            0, 7, 17,
            0, 7, 8,
            0, 1, 13};

    private static final BigInteger[] INJECTION_CONSTANTS = { new BigInteger("6e9e40ae", 16),   new BigInteger("71927c02", 16),   new BigInteger("9a13d3b1", 16),   new BigInteger("daec32ad", 16),   new BigInteger("3d8951cf", 16),   new BigInteger("e1c9fe9a", 16),   new BigInteger("b806b54c", 16),   new BigInteger("acbbf417", 16),
            new BigInteger("d3622b3b", 16),   new BigInteger("a082762a", 16),   new BigInteger("9edcf1c0", 16),   new BigInteger("a9bada77", 16),   new BigInteger("7f91e46c", 16),   new BigInteger("cb0f6e4f", 16),   new BigInteger("265d9241", 16),   new BigInteger("b7bdeab0", 16),
            new BigInteger("6260c9e6", 16),   new BigInteger("ff50dd2a", 16),   new BigInteger("9036aa71", 16),   new BigInteger("ce161879", 16),   new BigInteger("d1307cdf", 16),   new BigInteger("89e456df", 16),   new BigInteger("f83133e2", 16),   new BigInteger("65f55c3d", 16),
            new BigInteger("94871b01", 16),   new BigInteger("b5d204cd", 16),   new BigInteger("583a3264", 16),   new BigInteger("5e165957", 16),   new BigInteger("4cbda964", 16),   new BigInteger("675fca47", 16),   new BigInteger("f4a3033e", 16),   new BigInteger("2a417322", 16),
            new BigInteger("3b61432f", 16),   new BigInteger("7f5532f2", 16),   new BigInteger("b609973b", 16),   new BigInteger("1a795239", 16),   new BigInteger("31b477c9", 16),   new BigInteger("d2949d28", 16),   new BigInteger("78969712", 16),   new BigInteger("0eb87b6e", 16),
            new BigInteger("7e11d22d", 16),   new BigInteger("ccee88bd", 16),   new BigInteger("eed07eb8", 16),   new BigInteger("e5563a81", 16),   new BigInteger("e7cb6bcf", 16),   new BigInteger("25de953e", 16),   new BigInteger("4d05653a", 16),   new BigInteger("0b831557", 16),
            new BigInteger("94b9cd77", 16),   new BigInteger("13f01579", 16),   new BigInteger("794b4a4a", 16),   new BigInteger("67e7c7dc", 16),   new BigInteger("c456d8d4", 16),   new BigInteger("59689c9b", 16),   new BigInteger("668456d7", 16),   new BigInteger("22d2a2e1", 16),
            new BigInteger("38b3a828", 16),   new BigInteger("0315ac3c", 16),   new BigInteger("438d681e", 16),   new BigInteger("ab7109c5", 16),   new BigInteger("97ee19a8", 16),   new BigInteger("de062b2e", 16),   new BigInteger("2c76c47b", 16),   new BigInteger("0084456f", 16),
            new BigInteger("908f0fd3", 16),   new BigInteger("a646551f", 16),   new BigInteger("3e826725", 16),   new BigInteger("d521788e", 16),   new BigInteger("9f01c2b0", 16),   new BigInteger("93180cdc", 16),   new BigInteger("92ea1df8", 16),   new BigInteger("431a9aae", 16),
            new BigInteger("7c2ea356", 16),   new BigInteger("da33ad03", 16),   new BigInteger("46926893", 16),   new BigInteger("66bde7d7", 16),   new BigInteger("b501cc75", 16),   new BigInteger("1f6e8a41", 16),   new BigInteger("685250f4", 16),   new BigInteger("3bb1f318", 16),
            new BigInteger("af238c04", 16),   new BigInteger("974ed2ec", 16),   new BigInteger("5b159e49", 16),   new BigInteger("d526f8bf", 16),   new BigInteger("12085626", 16),   new BigInteger("3e2432a9", 16),   new BigInteger("6bd20c48", 16),   new BigInteger("1f1d59da", 16),
            new BigInteger("18ab1068", 16),   new BigInteger("80f83cf8", 16),   new BigInteger("2c8c11c0", 16),   new BigInteger("7d548035", 16),   new BigInteger("0ff675c3", 16),   new BigInteger("fed160bf", 16),   new BigInteger("74bbbb24", 16),   new BigInteger("d98e006b", 16),
            new BigInteger("deaa47eb", 16),   new BigInteger("05f2179e", 16),   new BigInteger("437b0b71", 16),   new BigInteger("a7c95f8f", 16),   new BigInteger("00a99d3b", 16),   new BigInteger("3fc3c444", 16),   new BigInteger("72686f8e", 16),   new BigInteger("00fd01a9", 16),
            new BigInteger("dedc0787", 16),   new BigInteger("c6af7626", 16),   new BigInteger("7012fe76", 16),   new BigInteger("f2a5f7ce", 16),   new BigInteger("9a7b2eda", 16),   new BigInteger("5e57fcf2", 16),   new BigInteger("4da0d4ad", 16),   new BigInteger("5c63b155", 16),
            new BigInteger("34117375", 16),   new BigInteger("d4134c11", 16),   new BigInteger("2ea77435", 16),   new BigInteger("5278b6de", 16),   new BigInteger("ab522c4c", 16),   new BigInteger("bc8fc702", 16),   new BigInteger("c94a09e4", 16),   new BigInteger("ebb93a9e", 16),
            new BigInteger("91ecb65e", 16),   new BigInteger("4c52ecc6", 16),   new BigInteger("8703bb52", 16),   new BigInteger("cb2d60aa", 16),   new BigInteger("30a0538a", 16),   new BigInteger("1514f10b", 16),   new BigInteger("157f6329", 16),   new BigInteger("3429dc3d", 16),
            new BigInteger("5db73eb2", 16),   new BigInteger("a7a1a969", 16),   new BigInteger("7286bd24", 16),   new BigInteger("0df6881e", 16),   new BigInteger("3785ba5f", 16),   new BigInteger("cd04623a", 16),   new BigInteger("02758170", 16),   new BigInteger("d827f556", 16),
            new BigInteger("99d95191", 16),   new BigInteger("84457eb1", 16),   new BigInteger("58a7fb22", 16),   new BigInteger("d2967c5f", 16),   new BigInteger("4f0c33f6", 16),   new BigInteger("4a02099a", 16),   new BigInteger("e0904821", 16),   new BigInteger("94124036", 16),
            new BigInteger("496a031b", 16),   new BigInteger("780b69c4", 16),   new BigInteger("cf1a4927", 16),   new BigInteger("87a119b8", 16),   new BigInteger("cdfaf4f8", 16),   new BigInteger("4cf9cd0f", 16),   new BigInteger("27c96a84", 16),   new BigInteger("6d11117e", 16),
            new BigInteger("7f8cf847", 16),   new BigInteger("74ceede5", 16),   new BigInteger("c88905e6", 16),   new BigInteger("60215841", 16),   new BigInteger("7172875a", 16),   new BigInteger("736e993a", 16),   new BigInteger("010aa53c", 16),   new BigInteger("43d53c2b", 16),
            new BigInteger("f0d91a93", 16),   new BigInteger("0d983b56", 16),   new BigInteger("f816663c", 16),   new BigInteger("e5d13363", 16),   new BigInteger("0a61737c", 16),   new BigInteger("09d51150", 16),   new BigInteger("83a5ac2f", 16),   new BigInteger("3e884905", 16),
            new BigInteger("7b01aeb5", 16),   new BigInteger("600a6ea7", 16),   new BigInteger("b7678f7b", 16),   new BigInteger("72b38977", 16),   new BigInteger("068018f2", 16),   new BigInteger("ce6ae45b", 16),   new BigInteger("29188aa8", 16),   new BigInteger("e5a0b1e9", 16),
            new BigInteger("c04c2b86", 16),   new BigInteger("8bd14d75", 16),   new BigInteger("648781f3", 16),   new BigInteger("dbae1e0a", 16),   new BigInteger("ddcdd8ae", 16),   new BigInteger("ab4d81a3", 16),   new BigInteger("446baaba", 16),   new BigInteger("1cc0c19d", 16),
            new BigInteger("17be4f90", 16),   new BigInteger("82c0e65d", 16),   new BigInteger("676f9c95", 16),   new BigInteger("5c708db2", 16),   new BigInteger("6fd4c867", 16),   new BigInteger("a5106ef0", 16),   new BigInteger("19dde49d", 16),   new BigInteger("78182f95", 16),
            new BigInteger("d089cd81", 16),   new BigInteger("a32e98fe", 16),   new BigInteger("be306c82", 16),   new BigInteger("6cd83d8c", 16),   new BigInteger("037f1bde", 16),   new BigInteger("0b15722d", 16),   new BigInteger("eddc1e22", 16),   new BigInteger("93c76559", 16),
            new BigInteger("8a2f571b", 16),   new BigInteger("92cc81b4", 16),   new BigInteger("021b7477", 16),   new BigInteger("67523904", 16),   new BigInteger("c95dbccc", 16),   new BigInteger("ac17ee9d", 16),   new BigInteger("944e46bc", 16),   new BigInteger("0781867e", 16),
            new BigInteger("c854dd9d", 16),   new BigInteger("26e2c30c", 16),   new BigInteger("858c0416", 16),   new BigInteger("6d397708", 16),   new BigInteger("ebe29c58", 16),   new BigInteger("c80ced86", 16),   new BigInteger("d496b4ab", 16),   new BigInteger("be45e6f5", 16),
            new BigInteger("10d24706", 16),   new BigInteger("acf8187a", 16),   new BigInteger("96f523cb", 16),   new BigInteger("2227e143", 16),   new BigInteger("78c36564", 16),   new BigInteger("4643adc2", 16),   new BigInteger("4729d97a", 16),   new BigInteger("cff93e0d", 16),
            new BigInteger("25484bbd", 16),   new BigInteger("91c6798e", 16),   new BigInteger("95f773f4", 16),   new BigInteger("44204675", 16),   new BigInteger("2eda57ba", 16),   new BigInteger("06d313ef", 16),   new BigInteger("eeaa4466", 16),   new BigInteger("2dfa7530", 16),
            new BigInteger("a8af0c9b", 16),   new BigInteger("39f1535e", 16),   new BigInteger("0cc2b7bd", 16),   new BigInteger("38a76c0e", 16),   new BigInteger("4f41071d", 16),   new BigInteger("cdaf2475", 16),   new BigInteger("49a6eff8", 16),   new BigInteger("01621748", 16),
            new BigInteger("36ebacab", 16),   new BigInteger("bd6d9a29", 16),   new BigInteger("44d1cd65", 16),   new BigInteger("40815dfd", 16),   new BigInteger("55fa5a1a", 16),   new BigInteger("87cce9e9", 16),   new BigInteger("ae559b45", 16),   new BigInteger("d76b4c26", 16),
            new BigInteger("637d60ad", 16),   new BigInteger("de29f5f9", 16),   new BigInteger("97491cbb", 16),   new BigInteger("fb350040", 16),   new BigInteger("ffe7f997", 16),   new BigInteger("201c9dcd", 16),   new BigInteger("e61320e9", 16),   new BigInteger("a90987a3", 16),
            new BigInteger("e24afa83", 16),   new BigInteger("61c1e6fc", 16),   new BigInteger("cc87ff62", 16),   new BigInteger("f1c9d8fa", 16),   new BigInteger("4fd04546", 16),   new BigInteger("90ecc76e", 16),   new BigInteger("46e456b9", 16),   new BigInteger("305dceb8", 16),
            new BigInteger("f627e68c", 16),   new BigInteger("2d286815", 16),   new BigInteger("c705bbfd", 16),   new BigInteger("101b6df3", 16),   new BigInteger("892dae62", 16),   new BigInteger("d5b7fb44", 16),   new BigInteger("ea1d5c94", 16),   new BigInteger("5332e3cb", 16),
            new BigInteger("f856f88a", 16),   new BigInteger("b341b0e9", 16),   new BigInteger("28408d9d", 16),   new BigInteger("5421bc17", 16),   new BigInteger("eb9af9bc", 16),   new BigInteger("602371c5", 16),   new BigInteger("67985a91", 16),   new BigInteger("d774907f", 16),
            new BigInteger("7c4d697d", 16),   new BigInteger("9370b0b8", 16),   new BigInteger("6ff5cebb", 16),   new BigInteger("7d465744", 16),   new BigInteger("674ceac0", 16),   new BigInteger("ea9102fc", 16),   new BigInteger("0de94784", 16),   new BigInteger("c793de69", 16),
            new BigInteger("fe599bb1", 16),   new BigInteger("c6ad952f", 16),   new BigInteger("6d6ca9c3", 16),   new BigInteger("928c3f91", 16),   new BigInteger("f9022f05", 16),   new BigInteger("24a164dc", 16),   new BigInteger("e5e98cd3", 16),   new BigInteger("7649efdb", 16),
            new BigInteger("6df3bcdb", 16),   new BigInteger("5d1e9ff1", 16),   new BigInteger("17f5d010", 16),   new BigInteger("e2686ea1", 16),   new BigInteger("6eac77fe", 16),   new BigInteger("7bb5c585", 16),   new BigInteger("88d90cbb", 16),   new BigInteger("18689163", 16),
            new BigInteger("67c9efa5", 16),   new BigInteger("c0b76d9b", 16),   new BigInteger("960efbab", 16),   new BigInteger("bd872807", 16),   new BigInteger("70f4c474", 16),   new BigInteger("56c29d20", 16),   new BigInteger("d1541d15", 16),   new BigInteger("88137033", 16),
            new BigInteger("e3f02b3e", 16),   new BigInteger("b6d9b28d", 16),   new BigInteger("53a077ba", 16),   new BigInteger("eedcd29e", 16),   new BigInteger("a50a6c1d", 16),   new BigInteger("12c2801e", 16),   new BigInteger("52ba335b", 16),   new BigInteger("35984614", 16),
            new BigInteger("e2599aa8", 16),   new BigInteger("af94ed1d", 16),   new BigInteger("d90d4767", 16),   new BigInteger("202c7d07", 16),   new BigInteger("77bec4f4", 16),   new BigInteger("fa71bc80", 16),   new BigInteger("fc5c8b76", 16),   new BigInteger("8d0fbbfc", 16),
            new BigInteger("da366dc6", 16),   new BigInteger("8b32a0c7", 16),   new BigInteger("1b36f7fc", 16),   new BigInteger("6642dcbc", 16),   new BigInteger("6fe7e724", 16),   new BigInteger("8b5fa782", 16),   new BigInteger("c4227404", 16),   new BigInteger("3a7d1da7", 16),
            new BigInteger("517ed658", 16),   new BigInteger("8a18df6d", 16),   new BigInteger("3e5c9b23", 16),   new BigInteger("1fbd51ef", 16),   new BigInteger("1470601d", 16),   new BigInteger("3400389c", 16),   new BigInteger("676b065d", 16),   new BigInteger("8864ad80", 16),
            new BigInteger("ea6f1a9c", 16),   new BigInteger("2db484e1", 16),   new BigInteger("608785f0", 16),   new BigInteger("8dd384af", 16),   new BigInteger("69d26699", 16),   new BigInteger("409c4e16", 16),   new BigInteger("77f9986a", 16),   new BigInteger("7f491266", 16),
            new BigInteger("883ea6cf", 16),   new BigInteger("eaa06072", 16),   new BigInteger("fa2e5db5", 16),   new BigInteger("352594b4", 16),   new BigInteger("9156bb89", 16),   new BigInteger("a2fbbbfb", 16),   new BigInteger("ac3989c7", 16),   new BigInteger("6e2422b1", 16),
            new BigInteger("581f3560", 16),   new BigInteger("1009a9b5", 16),   new BigInteger("7e5ad9cd", 16),   new BigInteger("a9fc0a6e", 16),   new BigInteger("43e5998e", 16),   new BigInteger("7f8778f9", 16),   new BigInteger("f038f8e1", 16),   new BigInteger("5415c2e8", 16),
            new BigInteger("6499b731", 16),   new BigInteger("b82389ae", 16),   new BigInteger("05d4d819", 16),   new BigInteger("0f06440e", 16),   new BigInteger("f1735aa0", 16),   new BigInteger("986430ee", 16),   new BigInteger("47ec952c", 16),   new BigInteger("bf149cc5", 16),
            new BigInteger("b3cb2cb6", 16),   new BigInteger("3f41e8c2", 16),   new BigInteger("271ac51b", 16),   new BigInteger("48ac5ded", 16),   new BigInteger("f76a0469", 16),   new BigInteger("717bba4d", 16),   new BigInteger("4f5c90d6", 16),   new BigInteger("3b74f756", 16),
            new BigInteger("1824110a", 16),   new BigInteger("a4fd43e3", 16),   new BigInteger("1eb0507c", 16),   new BigInteger("a9375c08", 16),   new BigInteger("157c59a7", 16),   new BigInteger("0cad8f51", 16),   new BigInteger("d66031a0", 16),   new BigInteger("abb5343f", 16),
            new BigInteger("e533fa43", 16),   new BigInteger("1996e2bb", 16),   new BigInteger("d7953a71", 16),   new BigInteger("d2529b94", 16),   new BigInteger("58f0fa07", 16),   new BigInteger("4c9b1877", 16),   new BigInteger("057e990d", 16),   new BigInteger("8bfe19c4", 16),
            new BigInteger("a8e2c0c9", 16),   new BigInteger("99fcaada", 16),   new BigInteger("69d2aaca", 16),   new BigInteger("dc1c4642", 16),   new BigInteger("f4d22307", 16),   new BigInteger("7fe27e8c", 16),   new BigInteger("1366aa07", 16),   new BigInteger("1594e637", 16),
            new BigInteger("ce1066bf", 16),   new BigInteger("db922552", 16),   new BigInteger("9930b52a", 16),   new BigInteger("aeaa9a3e", 16),   new BigInteger("31ff7eb4", 16),   new BigInteger("5e1f945a", 16),   new BigInteger("150ac49c", 16),   new BigInteger("0ccdac2d", 16),
            new BigInteger("d8a8a217", 16),   new BigInteger("b82ea6e5", 16),   new BigInteger("d6a74659", 16),   new BigInteger("67b7e3e6", 16),   new BigInteger("836eef4a", 16),   new BigInteger("b6f90074", 16),   new BigInteger("7fa3ea4b", 16),   new BigInteger("cb038123", 16),
            new BigInteger("bf069f55", 16),   new BigInteger("1fa83fc4", 16),   new BigInteger("d6ebdb23", 16),   new BigInteger("16f0a137", 16),   new BigInteger("19a7110d", 16),   new BigInteger("5ff3b55f", 16),   new BigInteger("fb633868", 16),   new BigInteger("b466f845", 16),
            new BigInteger("bce0c198", 16),   new BigInteger("88404296", 16),   new BigInteger("ddbdd88b", 16),   new BigInteger("7fc52546", 16),   new BigInteger("63a553f8", 16),   new BigInteger("a728405a", 16),   new BigInteger("378a2bce", 16),   new BigInteger("6862e570", 16),
            new BigInteger("efb77e7d", 16),   new BigInteger("c611625e", 16),   new BigInteger("32515c15", 16),   new BigInteger("6984b765", 16),   new BigInteger("e8405976", 16),   new BigInteger("9ba386fd", 16),   new BigInteger("d4eed4d9", 16),   new BigInteger("f8fe0309", 16),
            new BigInteger("0ce54601", 16),   new BigInteger("baf879c2", 16),   new BigInteger("d8524057", 16),   new BigInteger("1d8c1d7a", 16),   new BigInteger("72c0a3a9", 16),   new BigInteger("5a1ffbde", 16),   new BigInteger("82f33a45", 16),   new BigInteger("5143f446", 16),
            new BigInteger("29c7e182", 16),   new BigInteger("e536c32f", 16),   new BigInteger("5a6f245b", 16),   new BigInteger("44272adb", 16),   new BigInteger("cb701d9c", 16),   new BigInteger("f76137ec", 16),   new BigInteger("0841f145", 16),   new BigInteger("e7042ecc", 16),
            new BigInteger("f1277dd7", 16),   new BigInteger("745cf92c", 16),   new BigInteger("a8fe65fe", 16),   new BigInteger("d3e2d7cf", 16),   new BigInteger("54c513ef", 16),   new BigInteger("6079bc2d", 16),   new BigInteger("b66336b0", 16),   new BigInteger("101e383b", 16),
            new BigInteger("bcd75753", 16),   new BigInteger("25be238a", 16),   new BigInteger("56a6f0be", 16),   new BigInteger("eeffcc17", 16),   new BigInteger("5ea31f3d", 16),   new BigInteger("0ae772f5", 16),   new BigInteger("f76de3de", 16),   new BigInteger("1bbecdad", 16),
            new BigInteger("c9107d43", 16),   new BigInteger("f7e38dce", 16),   new BigInteger("618358cd", 16),   new BigInteger("5c833f04", 16),   new BigInteger("f6975906", 16),   new BigInteger("de4177e5", 16),   new BigInteger("67d314dc", 16),   new BigInteger("b4760f3e", 16),
            new BigInteger("56ce5888", 16),   new BigInteger("0e8345a8", 16),   new BigInteger("bff6b1bf", 16),   new BigInteger("78dfb112", 16),   new BigInteger("f1709c1e", 16),   new BigInteger("7bb8ed8b", 16),   new BigInteger("902402b9", 16),   new BigInteger("daa64ae0", 16),
            new BigInteger("46b71d89", 16),   new BigInteger("7eee035f", 16),   new BigInteger("be376509", 16),   new BigInteger("99648f3a", 16),   new BigInteger("0863ea1f", 16),   new BigInteger("49ad8887", 16),   new BigInteger("79bdecc5", 16),   new BigInteger("3c10b568", 16),
            new BigInteger("5f2e4bae", 16),   new BigInteger("04ef20ab", 16),   new BigInteger("72f8ce7b", 16),   new BigInteger("521e1ebe", 16),   new BigInteger("14525535", 16),   new BigInteger("2e8af95b", 16),   new BigInteger("9094ccfd", 16),   new BigInteger("bcf36713", 16),
            new BigInteger("c73953ef", 16),   new BigInteger("d4b91474", 16),   new BigInteger("6554ec2d", 16),   new BigInteger("e3885c96", 16),   new BigInteger("03dc73b7", 16),   new BigInteger("931688a9", 16),   new BigInteger("cbbef182", 16),   new BigInteger("2b77cfc9", 16),
            new BigInteger("632a32bd", 16),   new BigInteger("d2115dcc", 16),   new BigInteger("1ae5533d", 16),   new BigInteger("32684e13", 16),   new BigInteger("4cc5a004", 16),   new BigInteger("13321bde", 16),   new BigInteger("62cbd38d", 16),   new BigInteger("78383a3b", 16),
            new BigInteger("d00686f1", 16),   new BigInteger("9f601ee7", 16),   new BigInteger("7eaf23de", 16),   new BigInteger("3110c492", 16),   new BigInteger("9c351209", 16),   new BigInteger("7eb89d52", 16),   new BigInteger("6d566eac", 16),   new BigInteger("c2efd226", 16),
            new BigInteger("32e9fac5", 16),   new BigInteger("52227274", 16),   new BigInteger("09f84725", 16),   new BigInteger("b8d0b605", 16),   new BigInteger("72291f02", 16),   new BigInteger("71b5c34b", 16),   new BigInteger("3dbfcbb8", 16),   new BigInteger("04a02263", 16),
            new BigInteger("55ba597f", 16),   new BigInteger("d4e4037d", 16),   new BigInteger("c813e1be", 16),   new BigInteger("ffddeefa", 16),   new BigInteger("c3c058f3", 16),   new BigInteger("87010f2e", 16),   new BigInteger("1dfcf55f", 16),   new BigInteger("c694eeeb", 16),
            new BigInteger("a9c01a74", 16),   new BigInteger("98c2fc6b", 16),   new BigInteger("e57e1428", 16),   new BigInteger("dd265a71", 16),   new BigInteger("836b956d", 16),   new BigInteger("7e46ab1a", 16),   new BigInteger("5835d541", 16),   new BigInteger("50b32505", 16),
            new BigInteger("e640913c", 16),   new BigInteger("bb486079", 16),   new BigInteger("fe496263", 16),   new BigInteger("113c5b69", 16),   new BigInteger("93cd6620", 16),   new BigInteger("5efe823b", 16),   new BigInteger("2d657b40", 16),   new BigInteger("b46dfc6c", 16),
            new BigInteger("57710c69", 16),   new BigInteger("fe9fadeb", 16),   new BigInteger("b5f8728a", 16),   new BigInteger("e3224170", 16),   new BigInteger("ca28b751", 16),   new BigInteger("fdabae56", 16),   new BigInteger("5ab12c3c", 16),   new BigInteger("a697c457", 16),
            new BigInteger("d28fa2b7", 16),   new BigInteger("056579f2", 16),   new BigInteger("9fd9d810", 16),   new BigInteger("e3557478", 16),   new BigInteger("d88d89ab", 16),   new BigInteger("a72a9422", 16),   new BigInteger("6d47abd0", 16),   new BigInteger("405bcbd9", 16),
            new BigInteger("6f83ebaf", 16),   new BigInteger("13caec76", 16),   new BigInteger("fceb9ee2", 16),   new BigInteger("2e922df7", 16),   new BigInteger("ce9856df", 16),   new BigInteger("c05e9322", 16),   new BigInteger("2772c854", 16),   new BigInteger("b67f2a32", 16),
            new BigInteger("6d1af28d", 16),   new BigInteger("3a78cf77", 16),   new BigInteger("dff411e4", 16),   new BigInteger("61c74ca9", 16),   new BigInteger("ed8b842e", 16),   new BigInteger("72880845", 16),   new BigInteger("6e857085", 16),   new BigInteger("c6404932", 16),
            new BigInteger("ee37f6bc", 16),   new BigInteger("27116f48", 16),   new BigInteger("5e9ec45a", 16),   new BigInteger("8ea2a51f", 16),   new BigInteger("a5573db7", 16),   new BigInteger("a746d036", 16),   new BigInteger("486b4768", 16),   new BigInteger("5b438f3b", 16),
            new BigInteger("18c54a5c", 16),   new BigInteger("64fcf08e", 16),   new BigInteger("e993cdc1", 16),   new BigInteger("35c1ead3", 16),   new BigInteger("9de07de7", 16),   new BigInteger("321b841c", 16),   new BigInteger("87423c5e", 16),   new BigInteger("071aa0f6", 16),
            new BigInteger("962eb75b", 16),   new BigInteger("bb06bdd2", 16),   new BigInteger("dcdb5363", 16),   new BigInteger("389752f2", 16),   new BigInteger("83d9cc88", 16),   new BigInteger("d014adc6", 16),   new BigInteger("c71121bb", 16),   new BigInteger("2372f938", 16),
            new BigInteger("caff2650", 16),   new BigInteger("62be8951", 16),   new BigInteger("56dccaff", 16),   new BigInteger("ac4084c0", 16),   new BigInteger("09712e95", 16),   new BigInteger("1d3c288f", 16),   new BigInteger("1b085744", 16),   new BigInteger("e1d3cfef", 16),
            new BigInteger("5c9a812e", 16),   new BigInteger("6611fd59", 16),   new BigInteger("85e46044", 16),   new BigInteger("1981d885", 16),   new BigInteger("5a4c903f", 16),   new BigInteger("43f30d4b", 16),   new BigInteger("7d1d601b", 16),   new BigInteger("dd3c3391", 16),
            new BigInteger("030ec65e", 16),   new BigInteger("c12878cd", 16),   new BigInteger("72e795fe", 16),   new BigInteger("d0c76abd", 16),   new BigInteger("1ec085db", 16),   new BigInteger("7cbb61fa", 16),   new BigInteger("93e8dd1e", 16),   new BigInteger("8582eb06", 16),
            new BigInteger("73563144", 16),   new BigInteger("049d4e7e", 16),   new BigInteger("5fd5aefe", 16),   new BigInteger("7b842a00", 16),   new BigInteger("75ced665", 16),   new BigInteger("bb32d458", 16),   new BigInteger("4e83bba7", 16),   new BigInteger("8f15151f", 16),
            new BigInteger("7795a125", 16),   new BigInteger("f0842455", 16),   new BigInteger("499af99d", 16),   new BigInteger("565cc7fa", 16),   new BigInteger("a3b1278d", 16),   new BigInteger("3f27ce74", 16),   new BigInteger("96ca058e", 16),   new BigInteger("8a497443", 16),
            new BigInteger("a6fb8cae", 16),   new BigInteger("c115aa21", 16),   new BigInteger("17504923", 16),   new BigInteger("e4932402", 16),   new BigInteger("aea886c2", 16),   new BigInteger("8eb79af5", 16),   new BigInteger("ebd5ea6b", 16),   new BigInteger("c7980d3b", 16),
            new BigInteger("71369315", 16),   new BigInteger("796e6a66", 16),   new BigInteger("3a7ec708", 16),   new BigInteger("b05175c8", 16),   new BigInteger("e02b74e7", 16),   new BigInteger("eb377ad3", 16),   new BigInteger("6c8c1f54", 16),   new BigInteger("b980c374", 16),
            new BigInteger("59aee281", 16),   new BigInteger("449cb799", 16),   new BigInteger("e01f5605", 16),   new BigInteger("ed0e085e", 16),   new BigInteger("c9a1a3b4", 16),   new BigInteger("aac481b1", 16),   new BigInteger("c935c39c", 16),   new BigInteger("b7d8ce7f", 16) };

    private static final int NUM_ROUNDS = 43;
    private static final int CAPACITY = 256;
    private static final int RATE = 256;
    private static final BigInteger DELIMITER = new BigInteger("6", 16);

	// for eaglesong-256
	private static final int OutputLengthInBytes = 32;

	private Wire[] unpaddedInputs;

	private int totalLengthInBytes;

	private Wire[] output;

	public EaglesongGadget(Wire[] ins, int totalLengthInBytes, String... desc) {

		super(desc);

		this.unpaddedInputs = ins;
		this.totalLengthInBytes = totalLengthInBytes;

		buildCircuit();
	}

	private void printState(Wire[] state) {
        for (int i = 0; i < (RATE + CAPACITY) / 32; i++) {
            generator.addDebugInstruction(state[i], "state"+i);
        }
    }

	protected void buildCircuit() {
        Wire[] state = new Wire[(RATE + CAPACITY) / 32];
        Arrays.fill(state, generator.getZeroWire());

        int cBytesRemaining = totalLengthInBytes;
		int chunk_index = 0;
		while (cBytesRemaining >= RATE / 8) {
            for (int i = 0; i < RATE / 32; i++) {
                Wire number = generator.getZeroWire();
                for (int j = 0; j < 32 / 8; j++) {
                    number = number.shiftLeft(32, 8).xorBitwise(unpaddedInputs[chunk_index * RATE / 8 + i * 4 + j], 32);
                }
                state[i] = state[i].xorBitwise(number, 32);
            }
            permutation(state);

            cBytesRemaining = cBytesRemaining - RATE / 8;
            chunk_index = chunk_index + 1;
		}

		// last chunk
        for (int i = 0; i < RATE / 32; i++) {
            Wire number = generator.getZeroWire();
            for (int j = 0; j < 32 / 8; j++) {
                if (chunk_index * RATE / 8 + i * 4 + j < totalLengthInBytes) {
                    number = number.shiftLeft(32, 8).xorBitwise(unpaddedInputs[chunk_index * RATE / 8 + i * 4 + j], 32);
                } else if (chunk_index * RATE / 8 + i * 4 + j == totalLengthInBytes) {
                    number = number.shiftLeft(32, 8).xorBitwise(DELIMITER, 254).trimBits(254, 32);
                }
            }
            state[i] = state[i].xorBitwise(number, 32);
        }
        permutation(state);

		output = new Wire[OutputLengthInBytes];
		for (int i = 0; i < RATE / 32; i++) {
			Wire[] bits = state[i].getBitWires(32).packBitsIntoWords(8);
			for (int j = 0; j < 4; j++) {
				output[j + i * 4] = bits[j];
			}
		}
	}

	private void permutation(Wire[] state) {
        for (int i = 0; i < NUM_ROUNDS; i++) {
            applyBitMatrix(state);
            applyCirculantMultiplication(state);
            injectConstants(state, i);
            applyARA(state);
        }
    }

    private void applyBitMatrix(Wire[] state) {
        Wire[] new_state = new Wire[(RATE + CAPACITY) / 32];
        Arrays.fill(new_state, generator.getZeroWire());
        for (int i = 0; i < (RATE + CAPACITY) / 32; i++) {
            for (int j = 0; j < (RATE + CAPACITY) / 32; j++) {
                if (BIT_MATRIX[j * (RATE + CAPACITY) / 32 + i] == 1) {
                    new_state[i] = new_state[i].xorBitwise(state[j], 32);
                }
            }
        }
        for (int i = 0; i < (RATE + CAPACITY) / 32; i++) {
            state[i] = new_state[i];
        }
    }

    private void applyCirculantMultiplication(Wire[] state) {
        for (int i = 0; i < (RATE + CAPACITY) / 32; i++) {
            Wire tmp = state[i].rotateLeft(32, COEFFICIENTS[ 3 * i + 1]);
            Wire tmp1 = state[i].rotateLeft(32, COEFFICIENTS[ 3 * i + 2]);
            Wire tmp2 = tmp.xorBitwise(tmp1, 32);
            state[i] = state[i].xorBitwise(tmp2, 32);
        }
    }

    private void injectConstants(Wire[] state, int round) {
        for (int i = 0; i < (RATE + CAPACITY) / 32; i++) {
            state[i] = state[i].xorBitwise(INJECTION_CONSTANTS[round * (RATE + CAPACITY) / 32 + i], 254).trimBits(254, 32);
        }
    }

    private void applyARA(Wire[] state) {
        for (int i = 0; i < (RATE + CAPACITY) / 32; i = i + 2) {
            state[i] = state[i].add(state[i + 1]).trimBits(33, 32);
            state[i] = state[i].rotateLeft(32, 8);
            state[i + 1] = state[i + 1].rotateLeft(32, 24);
            state[i + 1] = state[i].add(state[i + 1]).trimBits(33, 32);
        }
    }

	/**
	 * outputs digest as 32-bit words
	 */
	@Override
	public Wire[] getOutputWires() {
		return output;
	}
}
