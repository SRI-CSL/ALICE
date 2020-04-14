

#include <assert.h>
sys/random.h

int main() {
#if defined (__stub_getentropy) || defined (__stub___getentropy)
  fail fail fail
#else
  getentropy();
#endif

  return 0;
}
