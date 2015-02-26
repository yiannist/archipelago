#ifndef NOTIFY_H
#define NOTIFY_H

typedef enum {REF_INC, REF_PLUS2, REF_DEC, REF_MINUS2} ref_change;

// TODO: Add proper type for obj.
int notify_gc(char *obj, ref_change change);

#endif /* NOTIFY_H */
