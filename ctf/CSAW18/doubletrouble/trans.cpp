#include <iostream>
#include <iomanip>
#include <math.h>
#include <stdio.h>
using namespace std;

int main()
{
	unsigned long long x = 0x4141414141414141;
	scanf("%lu", &x);
	double y = *(double*)&x;
	cout<<setprecision(30)<<y<<endl;

}
