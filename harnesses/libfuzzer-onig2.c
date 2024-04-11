#include <stdint.h>
#include <string.h>
#include <oniguruma.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    OnigRegex regex;
    OnigErrorInfo einfo;
    OnigEncoding encoding = ONIG_ENCODING_UTF8;
    OnigSyntaxType *syntax = ONIG_SYNTAX_DEFAULT;
    OnigOptionType option = ONIG_OPTION_DEFAULT;

    if (Size == 0)
        return 0;

    uint8_t *pattern = malloc(Size);
    if (!pattern)
        return 0;

    memcpy(pattern, Data, Size);

    int result = onig_new(&regex, pattern, pattern + Size, option, encoding, syntax, &einfo);
    if (result != ONIG_NORMAL)
    {
        onig_error_code_to_str(pattern, result, &einfo);
    }
    else
    {
        onig_free(regex);
    }

    free(pattern);
    return 0;
}