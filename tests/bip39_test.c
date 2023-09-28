#include <aws/testing/aws_test_harness.h>

#include <assert.h>
#include <aws/nitro_enclaves/bip39.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int count_words(const char *str) {
    int wordCount = 0;
    int inWord = 0; // Indicates if we are inside a word

    for (size_t i = 0; str[i] != '\0'; i++) {
        if (str[i] == ' ' || str[i] == '\n' || str[i] == '\t') {
            // We are outside a word
            inWord = 0;
        } else if (!inWord) {
            // We have entered a new word
            inWord = 1;
            wordCount++;
        }
    }

    return wordCount;
}

AWS_TEST_CASE(test_bip39_get_mnemonic_12_words, s_test_bip39_get_mnemonic_12_words)
static int s_test_bip39_get_mnemonic_12_words(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int numWords = 12;
    char *mnemonic = get_mnemonic(numWords);
    int wordCount = count_words(mnemonic);

    ASSERT_TRUE(mnemonic != NULL);
    ASSERT_TRUE(wordCount == numWords);

    return SUCCESS;
}

AWS_TEST_CASE(test_bip39_get_mnemonic_15_words, s_test_bip39_get_mnemonic_15_words)
static int s_test_bip39_get_mnemonic_15_words(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int numWords = 15;
    char *mnemonic = get_mnemonic(numWords);
    int wordCount = count_words(mnemonic);

    ASSERT_TRUE(mnemonic != NULL);
    ASSERT_TRUE(wordCount == numWords);

    return SUCCESS;
}

AWS_TEST_CASE(test_bip39_get_mnemonic_18_words, s_test_bip39_get_mnemonic_18_words)
static int s_test_bip39_get_mnemonic_18_words(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int numWords = 18;
    char *mnemonic = get_mnemonic(numWords);
    int wordCount = count_words(mnemonic);

    ASSERT_TRUE(mnemonic != NULL);
    ASSERT_TRUE(wordCount == numWords);

    return SUCCESS;
}

AWS_TEST_CASE(test_bip39_get_mnemonic_21_words, s_test_bip39_get_mnemonic_21_words)
static int s_test_bip39_get_mnemonic_21_words(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int numWords = 21;
    char *mnemonic = get_mnemonic(numWords);
    int wordCount = count_words(mnemonic);

    ASSERT_TRUE(mnemonic != NULL);
    ASSERT_TRUE(wordCount == numWords);

    return SUCCESS;
}

AWS_TEST_CASE(test_bip39_get_mnemonic_24_words, s_test_bip39_get_mnemonic_24_words)
static int s_test_bip39_get_mnemonic_24_words(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int numWords = 24;
    char *mnemonic = get_mnemonic(numWords);
    int wordCount = count_words(mnemonic);

    ASSERT_TRUE(mnemonic != NULL);
    ASSERT_TRUE(wordCount == numWords);

    return SUCCESS;
}