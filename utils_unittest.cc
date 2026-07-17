#include "utils.h"
#include <gtest/gtest.h>
#include <unistd.h>
#include <string>

TEST(Utils, getHomeDirectory){
  if (std::getenv("GITHUB_ACTIONS") != nullptr) {
    GTEST_SKIP() << "Skipping getlogin test in GitHub Actions environment";
  }

  std::string home_dir = Utils::getHomeDirectory();
  char* user = getlogin();
  std::string expected_path("/home/");
  expected_path.append(user);
  ASSERT_EQ(expected_path, home_dir);
}

TEST(Utils, getHomeDirectory_getpwuid){
  if (std::getenv("GITHUB_ACTIONS") != nullptr) {
    GTEST_SKIP() << "Skipping getlogin test in GitHub Actions environment";
  }

  char* home_env= getenv("HOME");
  unsetenv("HOME");
  std::string home_dir = Utils::getHomeDirectory();
  char* user = getlogin();
  std::string expected_path("/home/");
  expected_path.append(user);
  setenv("HOME",home_env,0);
  ASSERT_EQ(expected_path, home_dir);
}

TEST(Utils, getDataDirectory){
  if (std::getenv("GITHUB_ACTIONS") != nullptr) {
    GTEST_SKIP() << "Skipping getlogin test in GitHub Actions environment";
  }

  std::string actual = Utils::getDataDirectory();
  char* user = getlogin();
  std::string expected_path("/home/");
  expected_path.append(user);
  expected_path.append("/.local/share/rammini.com/checksums");
  ASSERT_EQ(expected_path, actual);
}

TEST(Utils, getDateWithMonthAsText){
  std::string actual = Utils::getDateWithMonthAsText("2012-05-26");
  std::string expected("2012-May-26");
  ASSERT_EQ(expected, actual);
}

TEST(Utils, getDateWithMonthAsEmpty){
  std::string actual = Utils::getDateWithMonthAsText("");
  std::string expected("");
  ASSERT_EQ(expected, actual);
}

TEST(Utils, getDateWithMonthAsError){
  std::string actual = Utils::getDateWithMonthAsText("A12-05-26");
  std::string expected("");
  ASSERT_EQ(expected, actual);
}

TEST(Utils, getDateWithMonthAsError_Month){
  std::string actual = Utils::getDateWithMonthAsText("2012-20-26");
  std::string expected("");
  ASSERT_EQ(expected, actual);
}

TEST(Utils, getDateWithMonthAsError_Day){
  std::string actual = Utils::getDateWithMonthAsText("2012-05-40");
  std::string expected("");
  ASSERT_EQ(expected, actual);
}

TEST(Utils, isValidEmail_ValidSimple){
  ASSERT_TRUE(Utils::isValidEmail("user@example.com"));
}

TEST(Utils, isValidEmail_ValidSubdomain){
  ASSERT_TRUE(Utils::isValidEmail("user@mail.example.co.uk"));
}

TEST(Utils, isValidEmail_InValidSubdomain_LessThanTwo){
  ASSERT_FALSE(Utils::isValidEmail("user@mail.example.co.u"));
}

TEST(Utils, isValidEmail_InvalidNoAt){
  ASSERT_FALSE(Utils::isValidEmail("userexample.com"));
}

TEST(Utils, isValidEmail_InvalidMultipleAt){
  ASSERT_FALSE(Utils::isValidEmail("user@@example.com"));
}

TEST(Utils, isValidEmail_InvalidLeadingDotLocal){
  ASSERT_FALSE(Utils::isValidEmail(".user@example.com"));
}

TEST(Utils, isValidEmail_InvalidTrailingDotDomain){
  ASSERT_FALSE(Utils::isValidEmail("user@example.com."));
}

TEST(Utils, isValidEmail_ValidPlusAddressing){
  ASSERT_TRUE(Utils::isValidEmail("user+tag@example.com"));
}

TEST(Utils, isValidEmail_InvalidEmpty){
  ASSERT_FALSE(Utils::isValidEmail(""));
}

TEST(Utils, isValidEmail_InvalidSpace){
  ASSERT_FALSE(Utils::isValidEmail("user @example.com"));
}

