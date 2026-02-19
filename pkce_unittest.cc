#include "pkce.h"
#include <gtest/gtest.h>
#include <unistd.h>
#include <string>


TEST(PKCE, getCodeVerifier){
  PKCE pkce;
  int expected_len= 128;
  for (int i=0; i< 1; i++){
    std::string code_verifier = pkce.getCodeVerifier();
    std::cout << code_verifier << "\n";
    ASSERT_EQ(expected_len, code_verifier.length());
    ASSERT_EQ(std::string::npos, code_verifier.find('+'));
    ASSERT_EQ(std::string::npos, code_verifier.find('/'));
    ASSERT_EQ(std::string::npos, code_verifier.find('='));
  }

}

TEST(PKCE, getCodeVerifierSha256){
  PKCE pkce;
  int expected_len= 128;
  std::string code_verifier = "TDcpRXD3RRGdwjtiYeFb3ujj68_DXoUwkltCiRWa3lb98yTqaabolHerzV6GKwOOP4L48UQvWiCUcT--BXIaFiAdQW_eguq-8NBJ0beaTYJ0o_b6QpzZEq9KXzQU6XSW";
  std::string sha256 = pkce.getCodeVerifierSha256(code_verifier);
  ASSERT_EQ("B585A49142504B8F19807759F2CA3449984FEBBF49AE7F9B1934643B0ED691C3", sha256);
}



