#include "api.h"
#include <gtest/gtest.h>
#include <unistd.h>
#include <string>
#include "third_party/json_parser/json_parser.h"



//Sha256 and Sha512 matched. (Public file.)
TEST(ApiTest, GetResultToDisplay_1) {
    Api api;
    std::string input = "{\"file_name\":\"test.exe\",\"sha512sum\":\"162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be\",\"sha256sum\":\"87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7\",\"release_date\":\"2025-05-22\",\"software_name\":\"TestSoft\",\"version\":\"1.0.1\",\"public\":1}";
    JsonParser parser;
    std::unique_ptr api_result = parser.parseJson(input);
    std::string expected = 
        "File name: test.exe\n"
        "\nSha512 matched!"
        "\nSha256 matched!"
        "\n\n<b><u>Checksums of selected file</u></b>"
        "\n\nSha 256 : 87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7"
        "\n\nSha 512 : 162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be"
        "\n\nSoftware: TestSoft"
        "\nVersion: 1.0.1"
        "\nRelease date: 2025-05-22";

    Result::RESULT_TYPE result_type;
    std::string local_sha256 = "87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7";
    std::string local_sha512 = "162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be";
    std::string result = api.getResultToDisplay(api_result.get(),local_sha256, local_sha512, result_type);

    EXPECT_EQ(result, expected);
}

//Sha256 matched. But Sha512 not available in our database. (Public file)
TEST(ApiTest, GetResultToDisplay_2) {
    Api api;
    std::string input = "{\"file_name\":\"test.exe\",\"sha512sum\":\"\",\"sha256sum\":\"87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7\",\"release_date\":\"2025-05-22\",\"software_name\":\"TestSoft\",\"public\":1}";
    JsonParser parser;
    std::unique_ptr api_result = parser.parseJson(input);
    std::string expected = 
        "File name: test.exe\n"
        "\nSha256 matched!"
        "\n\n<b><u>Checksums of selected file</u></b>"
        "\n\nSha 256 : 87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7"
        "\n\nSha 512 : 162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be"
        "\n\nSoftware: TestSoft"
        "\nVersion: "
        "\nRelease date: 2025-05-22"
        "\n\n<b>* <i>These checksums were not available in our database.</i></b>"
        "\nsha 512";

    Result::RESULT_TYPE result_type;
    std::string local_sha256 = "87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7";
    std::string local_sha512 = "162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be";
    std::string result = api.getResultToDisplay(api_result.get(),local_sha256, local_sha512, result_type);

    EXPECT_EQ(result, expected);
}

//Sha512 matched. But Sha256 not available in our database. (Public file)
TEST(ApiTest, GetResultToDisplay_3) {
    Api api;
    std::string input = "{\"file_name\":\"test.exe\",\"sha512sum\":\"162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be\",\"sha256sum\":\"\",\"release_date\":\"2025-05-22\",\"software_name\":\"TestSoft\",\"public\":1}";
    JsonParser parser;
    std::unique_ptr api_result = parser.parseJson(input);
    std::string expected = 
        "File name: test.exe\n"
        "\nSha512 matched!"
        "\n\n<b><u>Checksums of selected file</u></b>"
        "\n\nSha 256 : 87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7"
        "\n\nSha 512 : 162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be"
        "\n\nSoftware: TestSoft"
        "\nVersion: "
        "\nRelease date: 2025-05-22"
        "\n\n<b>* <i>These checksums were not available in our database.</i></b>"
        "\nsha 256";

    Result::RESULT_TYPE result_type;
    std::string local_sha256 = "87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7";
    std::string local_sha512 = "162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be";
    std::string result = api.getResultToDisplay(api_result.get(),local_sha256, local_sha512, result_type);

    EXPECT_EQ(result, expected);
}

//Checksums did not match. But similar file name found. (Public file)
TEST(ApiTest, GetResultToDisplay_4) {
    Api api;
    std::string input = "{\"file_name\":\"test.exe\",\"sha512sum\":\"f62b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be\",\"sha256sum\":\"f7428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7\",\"release_date\":\"2025-05-22\",\"software_name\":\"TestSoft\",\"public\":1}";
    JsonParser parser;
    std::unique_ptr api_result = parser.parseJson(input);
    std::string expected = 
        "File name: test.exe\n"
        "\nChecksums <b>DID NOT</b> match!"
        "\n\n<b><u>Checksums of selected file</u></b>"
        "\n\nSha 256 : 87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7"
        "\n\nSha 512 : 162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be"        
        "\n\n<b><u>Checksums in our Database</u></b>"
        "\n\nSha 256 : f7428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7"
        "\n\nSha 512 : f62b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be"
        "\n\nSoftware: TestSoft"
        "\nVersion: "
        "\nRelease date: 2025-05-22";

    Result::RESULT_TYPE result_type;
    std::string local_sha256 = "87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7";
    std::string local_sha512 = "162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be";
    std::string result = api.getResultToDisplay(api_result.get(),local_sha256, local_sha512, result_type);

    EXPECT_EQ(result, expected);
}

/*Checksums did not match. But similar file name found. (Public file)
  Sha256 not available in our database.
*/
TEST(ApiTest, GetResultToDisplay_5) {
    Api api;
    std::string input = "{\"file_name\":\"test.exe\",\"sha512sum\":\"f62b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be\",\"sha256sum\":\"\",\"release_date\":\"2025-05-22\",\"software_name\":\"TestSoft\",\"public\":1}";
    JsonParser parser;
    std::unique_ptr api_result = parser.parseJson(input);
    std::string expected = 
        "File name: test.exe\n"
        "\nChecksums <b>DID NOT</b> match!"
        "\n\n<b><u>Checksums of selected file</u></b>"
        "\n\nSha 256 : 87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7"
        "\n\nSha 512 : 162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be"
        "\n\n<b><u>Checksums in our Database</u></b>"
        "\n\nSha 512 : f62b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be"
        "\n\nSoftware: TestSoft"
        "\nVersion: "
        "\nRelease date: 2025-05-22"
        "\n\n<b>* <i>These checksums were not available in our database.</i></b>"
        "\nsha 256";

    Result::RESULT_TYPE result_type;
    std::string local_sha256 = "87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7";
    std::string local_sha512 = "162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be";
    std::string result = api.getResultToDisplay(api_result.get(),local_sha256, local_sha512, result_type);

    EXPECT_EQ(result, expected);
}

/*Checksums did not match. But similar file name found. (Public file)
  Sha512 not available in our database.
*/
TEST(ApiTest, GetResultToDisplay_6) {
    Api api;
    std::string input = "{\"file_name\":\"test.exe\",\"sha512sum\":\"\",\"sha256sum\":\"f7428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7\",\"release_date\":\"2025-05-22\",\"software_name\":\"TestSoft\",\"public\":1}";
    JsonParser parser;
    std::unique_ptr api_result = parser.parseJson(input);
    std::string expected = 
        "File name: test.exe\n"
        "\nChecksums <b>DID NOT</b> match!"
        "\n\n<b><u>Checksums of selected file</u></b>"
        "\n\nSha 256 : 87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7"
        "\n\nSha 512 : 162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be"
        "\n\n<b><u>Checksums in our Database</u></b>"
        "\n\nSha 256 : f7428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7"
        "\n\nSoftware: TestSoft"
        "\nVersion: "
        "\nRelease date: 2025-05-22"
        "\n\n<b>* <i>These checksums were not available in our database.</i></b>"
        "\nsha 512";

    Result::RESULT_TYPE result_type;
    std::string local_sha256 = "87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7";
    std::string local_sha512 = "162b0b32f02482d5aca0a7c93dd03ceac3acd7e410a5f18f3fb990fc958ae0df6f32233b91831eaf99ca581a8c4ddf9c8ba315ac482db6d4ea01cc7884a635be";
    std::string result = api.getResultToDisplay(api_result.get(),local_sha256, local_sha512, result_type);

    EXPECT_EQ(result, expected);
}

//Sha256 matched. (Private file.)
TEST(ApiTest, GetResultToDisplay_7) {
    Api api;
    std::string input = "{\"file_name\":\"test.xls\",\"sha512sum\":\"\",\"sha256sum\":\"a327c7ec122c0e521f528416a3bcefe04925b90cc1fae8db9aec787c039ac0bd\",\"release_date\":\"2025-05-22\",\"software_name\":\"TestSoft\",\"public\":0}";
    JsonParser parser;
    std::unique_ptr api_result = parser.parseJson(input);
    std::string expected = 
        "File name: test.xls"
        "\n(Personal file)"
        "\n\nSha256 matched!"
        "\n\n<b><u>Checksums of selected file</u></b>"
        "\n\nSha 256 : a327c7ec122c0e521f528416a3bcefe04925b90cc1fae8db9aec787c039ac0bd"
        "\n\nSha 512 : b373766264e123665d043678f255cd92f0358b02100b826d36edd0642c9deda0a74a5c6fe5719dba9a5d928a7b590824eb52bd130afeb7f01d79573c4dc06d9e"
        "\n\n<b>* <i>These checksums were not available in our database.</i></b>"
        "\nsha 512";

    Result::RESULT_TYPE result_type;
    std::string local_sha256 = "a327c7ec122c0e521f528416a3bcefe04925b90cc1fae8db9aec787c039ac0bd";
    std::string local_sha512 = "b373766264e123665d043678f255cd92f0358b02100b826d36edd0642c9deda0a74a5c6fe5719dba9a5d928a7b590824eb52bd130afeb7f01d79573c4dc06d9e";
    std::string result = api.getResultToDisplay(api_result.get(),local_sha256, local_sha512, result_type);

    EXPECT_EQ(result, expected);
}

//Checksums did not match. (Private file.)
TEST(ApiTest, GetResultToDisplay_8) {
    Api api;
    std::string input = "{\"file_name\":\"test.xls\",\"sha512sum\":\"\",\"sha256sum\":\"f327c7ec122c0e521f528416a3bcefe04925b90cc1fae8db9aec787c039ac0bd\",\"release_date\":\"2025-05-22\",\"software_name\":\"TestSoft\",\"public\":0}";
    JsonParser parser;
    std::unique_ptr api_result = parser.parseJson(input);
    std::string expected = 
        "File name: test.xls"
        "\n(Personal file)"
        "\n\nChecksums <b>DID NOT</b> match!"
        "\n\n<b><u>Checksums of selected file</u></b>"
        "\n\nSha 256 : a327c7ec122c0e521f528416a3bcefe04925b90cc1fae8db9aec787c039ac0bd"
        "\n\nSha 512 : b373766264e123665d043678f255cd92f0358b02100b826d36edd0642c9deda0a74a5c6fe5719dba9a5d928a7b590824eb52bd130afeb7f01d79573c4dc06d9e"
        "\n\n<b><u>Checksums in our Database</u></b>"
        "\n\nSha 256 : f327c7ec122c0e521f528416a3bcefe04925b90cc1fae8db9aec787c039ac0bd"
        "\n\n<b>* <i>These checksums were not available in our database.</i></b>"
        "\nsha 512";

    Result::RESULT_TYPE result_type;
    std::string local_sha256 = "a327c7ec122c0e521f528416a3bcefe04925b90cc1fae8db9aec787c039ac0bd";
    std::string local_sha512 = "b373766264e123665d043678f255cd92f0358b02100b826d36edd0642c9deda0a74a5c6fe5719dba9a5d928a7b590824eb52bd130afeb7f01d79573c4dc06d9e";
    std::string result = api.getResultToDisplay(api_result.get(),local_sha256, local_sha512, result_type);

    EXPECT_EQ(result, expected);
}