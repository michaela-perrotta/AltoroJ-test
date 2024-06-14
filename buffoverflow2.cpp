#include <stdio.h>
#include "TestCase_IOT_Instance.h"

/**
 * TestCase_IOT_Instance
 * <p/>
 * The results of assessing this file should be a input output stack trace
 * leading from getVulnerableSource to writeToVulnerableSink.  Unlike the TestCase_IOT_Static
 * class, all methods in this class are not static.  We do not use temporaries to store the
 * result of getVulnerableSource().
 * <p/>
 * Complexity: Easy
 */
namespace SimpleIOT {
    char *TestCase_IOT_Instance::getVulnerableSource(const char *file) {
        return getVulnerableBuffer(file);
	}

    void TestCase_IOT_Instance::writeToVulnerableSink(const char *file, const char *str) {
        writeVulnerableBuffer(file, str);
	}

    char* TestCase_IOT_Instance::getVulnerableBuffer(const char *file) {
        char *buf = new char[100];
        if (file != NULL) {
	  FILE * input_file = fopen (file, "r");
	  fgets(buf, 100, input_file);
	  fclose(input_file);
	}
        return buf;
	}

    extern FILE *fp ;
    void TestCase_IOT_Instance::writeVulnerableBuffer(const char *file, const char *buf) {
	// FIX ME change back to fwrite soon -- 3/28/2006
	//        ::fwrite(buf, 100, 100, fp);
	::fprintf(fp,"%s", buf);
    }
	
	
}

using namespace SimpleIOT;
int TestCase_IOT_Instance_main( int argc, char **args) {
    TestCase_IOT_Instance testCase;
    testCase.writeToVulnerableSink(args[1], testCase.getVulnerableSource(args[0]));
    return 0;
}
