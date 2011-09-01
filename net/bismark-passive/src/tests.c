#include "packet_series.h"

#include <stdlib.h>

#include <check.h>

static packet_series_t series;
static const int kMySize = 12;
static const int kMyFlowId = 1;
static const uint32_t kMySec = 100;
static const uint32_t kMyUSec = 20000;

void series_setup () {
  packet_series_init (&series);
}

void series_teardown () {
}

START_TEST (test_series_add) {
  struct timeval first_tv, second_tv;

  first_tv.tv_sec = kMySec;
  first_tv.tv_usec = kMyUSec;
  fail_if (packet_series_add_packet (&series, &first_tv, kMySize, kMyFlowId));
  fail_unless (series.length == 1);
  fail_unless (series.start_time.tv_sec == kMySec);
  fail_unless (series.start_time.tv_usec == kMyUSec);
  fail_if (series.discarded_by_overflow);
  fail_unless (series.packet_data[0].timestamp == 0);
  fail_unless (series.packet_data[0].size == kMySize);
  fail_unless (series.packet_data[0].flow == kMyFlowId);

  second_tv.tv_sec = kMySec * 2;
  second_tv.tv_usec = kMyUSec * 2;
  fail_if (packet_series_add_packet (&series, &second_tv, kMySize * 2, kMyFlowId));
  fail_unless (series.length == 2);
  fail_unless (series.start_time.tv_sec == first_tv.tv_sec);
  fail_unless (series.start_time.tv_usec == first_tv.tv_usec);
  fail_if (series.discarded_by_overflow);
  fail_unless (series.packet_data[1].timestamp
      == ((second_tv.tv_sec * NUM_MICROS_PER_SECOND + second_tv.tv_usec)
          - (kMySec * NUM_MICROS_PER_SECOND + kMyUSec)));
  fail_unless (series.packet_data[1].size == kMySize * 2);
  fail_unless (series.packet_data[1].flow == kMyFlowId);
}
END_TEST

START_TEST (test_series_overflow) {
  int idx;
  struct timeval tv;

  tv.tv_sec = kMySec;
  tv.tv_usec = kMyUSec;

  for (idx = 0; idx < PACKET_DATA_BUFFER_ENTRIES; ++idx) {
    fail_if (packet_series_add_packet (&series, &tv, kMySize, kMyFlowId));
    fail_unless (series.length == idx + 1);
    fail_unless (series.start_time.tv_sec == kMySec);
    fail_unless (series.start_time.tv_usec == kMyUSec);
    fail_if (series.discarded_by_overflow);
  }

  for (idx = 0; idx < 10; ++idx) {
    fail_unless (packet_series_add_packet (&series, &tv, kMySize, kMyFlowId));
    fail_unless (series.length == PACKET_DATA_BUFFER_ENTRIES);
    fail_unless (series.start_time.tv_sec == kMySec);
    fail_unless (series.start_time.tv_usec == kMyUSec);
    fail_unless (series.discarded_by_overflow == idx + 1);
  }
}
END_TEST

Suite* build_suite () {
  Suite *s = suite_create ("Bismark passive");

  TCase *tc_core = tcase_create ("Packet series");
  tcase_add_checked_fixture (tc_core, series_setup, series_teardown);
  tcase_add_test (tc_core, test_series_add);
  tcase_add_test (tc_core, test_series_overflow);
  suite_add_tcase (s, tc_core);

  return s;
}

int main (int argc, char* argv[]) {
  int number_failed;
  Suite *s = build_suite ();
  SRunner *sr = srunner_create (s);
  srunner_run_all (sr, CK_NORMAL);
  number_failed = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
