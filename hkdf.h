#ifndef _HKDF_H_
#define _HKDF_H_

int hkdf_extract(int, const unsigned char *, unsigned long,
                      const unsigned char *, unsigned long,
                            unsigned char *, unsigned long *);

int hkdf_expand(int,  const unsigned char *, unsigned long,
                      const unsigned char *, unsigned long,
                            unsigned char *, unsigned long);

int hkdf(int, const unsigned char *, unsigned long,
              const unsigned char *, unsigned long,
              const unsigned char *, unsigned long,
                    unsigned char *, unsigned long);
/* vim: set ts=2 sw=2 et ai si: */
#endif /* _HKDF_H_ */

