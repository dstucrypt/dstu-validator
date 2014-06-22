#include <openssl/asn1t.h>

typedef STACK_OF(ASN1_PRINTABLESTRING) NUMBERS;
DECLARE_STACK_OF(ASN1_PRINTABLESTRING);

typedef struct Tax_number_entry_st
    {
    ASN1_OBJECT *object;
    NUMBERS *value;
} TAX_NUMBER;

DECLARE_STACK_OF(TAX_NUMBER);
DECLARE_ASN1_SET_OF(TAX_NUMBER);

typedef STACK_OF(TAX_NUMBER) TAX_NUMBERS;

DECLARE_ASN1_FUNCTIONS(TAX_NUMBERS);

#define sk_TAX_NUMBER_num(st) SKM_sk_num(TAX_NUMBER, (st))
#define sk_TAX_NUMBER_value(st, i) SKM_sk_value(TAX_NUMBER, (st), (i))
#define sk_PS_value(st, i) SKM_sk_value(ASN1_PRINTABLESTRING, (st), (i))
