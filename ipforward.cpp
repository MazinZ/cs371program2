#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

string longToDottedIP(long ip);
vector<string> parser(string s);
bool matchesPrefix(string prefix, string ipAdd);
long reverseLong(long num);


struct line1 {
	unsigned char a;
	unsigned char b;
	unsigned char c;
	unsigned char d;
};

struct line2 {
	unsigned short a;
	unsigned char b;
	unsigned char c;
};

struct line3 {
	unsigned char a;
	unsigned char b;
	unsigned short c;
	
};

class tableEntry{
	public:
		 tableEntry(string soIP, string nM, string nH);
	
		
		string getSourceIP(){
			return sourceIP;
		}
		string getnetMask() {
			return netMask;
		}
		string getnextHop(){
			return nextHop;
		}

	private:
		string sourceIP;
		string netMask;
		string nextHop;
	
};




tableEntry::tableEntry(string soIP, string nM, string nH){
	sourceIP = soIP;
	netMask = nM;
	nextHop = nH;
}
tableEntry bestMatch(vector<tableEntry>);


/* Deleted code */

int main(int argc, char *argv[]) {
	FILE *fp;
	fp = fopen ("./ip_packets", "rb");
	while (!feof(fp)){
	line1 x;
	/*												*/
	
	
	fread(&x.a, 4, 1, fp);
	int version = (x.a & 0xF0) >> 4;
	int hlen = (x.a & 0x0F) * 4;
	int total_len = x.c * 256 + x.d;
	
	
	line2 y;
	
	fread(&y.a, 4, 1, fp);
	int identifier = y.a;
	
	
	line3 z;
	fread(&z, 4, 1, fp);


	int TTL = z.a;
	unsigned short checksum = z.c; // wrong, needs htons
	unsigned long sourceIP;
	unsigned long destIP;

	fread(&sourceIP, 4, 1, fp);
	fread(&destIP, 4, 1, fp);
	sourceIP = htonl(sourceIP);
	destIP = htonl(destIP);
	
	char *data;
	data = NULL;
	data = new char[total_len-20];
	fread(&data[0], 1, total_len-20, fp);
	int n=total_len-20, i =0;
	 char* byte_array = data;
if( feof(fp) )
	{
	   break;
	}
	while (i < n)
	{
		 printf(" %d. = %02d | ",i+1,(unsigned)byte_array[i]);
		 i++;
	}
	
	/*    					ROUTING TABLE PARSING					*/
	ifstream routingTable;
	routingTable.open("./routing_table.txt", ifstream::in);
	string line;
	vector<tableEntry> routingEntries;
	//Trie prefixtree;
	while (getline(routingTable, line))
	{
		
		vector<string> parsed;
		parsed = parser(line);
		tableEntry newTableEntry(parsed[0], parsed[1], parsed[2]);
		routingEntries.push_back(newTableEntry);
		//prefixtree.insert(parsed[0].substr(0, parsed[0].find_first_of(".0")+1));
	}
	routingTable.close();
	
	
	//cout << "TESTING: " << longToDottedIP(destIP) << endl;
	//prefixtree.search("137.34");
	bool matchFound = false;	
	string forwardedIP = "";
	vector<tableEntry> matchList;
	
	for (int i = 0; i <routingEntries.size()-1; i++) {
		//long testValue = reverseLong(inet_addr(routingEntries[i].getSourceIP().c_str())) & reverseLong(inet_addr(routingEntries[i].getnetMask().c_str())) ^ destIP & reverseLong(inet_addr(routingEntries[i].getnetMask().c_str()));
		long testValue = reverseLong(inet_addr(routingEntries[i].getSourceIP().c_str())) ^ destIP & reverseLong(inet_addr(routingEntries[i].getnetMask().c_str()));
		
		
		/*cout << endl;
		cout << reverseLong(inet_addr(routingEntries[i].getSourceIP().c_str())) << endl;
		cout << reverseLong(inet_addr(routingEntries[i].getnetMask().c_str())) << endl;
		cout << destIP << endl;*/
		
		
		//cout << "testval: " << testValue << endl;
		if (testValue == 0){
			matchFound = true;
			matchList.push_back(routingEntries[i]);
			forwardedIP = routingEntries[i].getnextHop();
			//cout << "Matching: " << routingEntries[i].getSourceIP() << endl;
		}
		
	
	}
	if (matchFound) {
		forwardedIP = bestMatch(matchList).getnextHop();
	}
	else {
		forwardedIP = routingEntries[routingEntries.size()-1].getSourceIP();

	}
	
	
	/*						OUTPUT FILE 							*/
	
	
	
	
	
	
	//								TESTING PRINT FOR ROUTING TABLE                      //
	
	/*for (int i = 0; i < routingEntries.size(); i++){
		cout << routingEntries[i].getSourceIP() << " " << routingEntries[i].getnetMask() << " " << routingEntries[i].getnextHop() << " " << endl;
	}*/
	
	
	/*long checksumArray[10] = [(x.a << 8) | (x.b), 
	(x.c << 8) | (x.d), 
	htons((y.a)), 
	(y.b << 8) | (y.b), 
	(z.a << 8) | (z.b),
	htons((z.c)),
	sourceIP & 0xffff0000) >> 16,
	(sourceIP & 0x0000ffff),
	(destIP & 0xffff0000) >> 16,
	(destIP & 0x0000ffff)
	];*/
	
	
	
	
	unsigned long mynum = (x.a << 8) | (x.b);
	unsigned long mynum2 = (x.c << 8) | (x.d);
	unsigned long mynum3 = htons((y.a));
	unsigned long mynum4 = (y.b << 8) | (y.b);
	unsigned long mynum5 = (z.a << 8) | (z.b);
	unsigned long mynum6 = htons((z.c));
	unsigned long mynum7 = (sourceIP & 0xffff0000) >> 16;
	unsigned long mynum8 = (sourceIP & 0x0000ffff);
	unsigned long mynum9 = (destIP & 0xffff0000) >> 16;
	unsigned long mynum10 = (destIP & 0x0000ffff);
	


	vector<unsigned long> nums;
	nums.push_back(mynum);
	nums.push_back(mynum2);
	nums.push_back(mynum3);
	nums.push_back(mynum4);
	nums.push_back(mynum5);
	nums.push_back(mynum6);
	nums.push_back(mynum7);
		nums.push_back(mynum8);
	nums.push_back(mynum9);
	nums.push_back(mynum10);

	unsigned long sum = 0;
	int j = 1;

	for (int i = 0; i < nums.size(); i+=1) {
		cout << "NUM: " << i+1 << " " << nums[i] << endl;
		cout << "NUM: " << j+1 << " " << nums[j] << endl;

		if (sum + nums[i] >= 65535) {
			sum += (nums[i] - 65536 + 1);
		}
		else {
			sum += nums[i];
 		}
		//j+=2;
	cout << "SUMCURR: " << sum << endl;
	}
		
	
	cout << "sum: " << sum << endl;
	
	cout << version << endl;
	cout << hlen << endl;
	cout << total_len << endl;
	cout << identifier << endl;
	cout << TTL << endl;
	cout << checksum << endl;
	cout << "SourceIP " << longToDottedIP(sourceIP) << endl;
	cout << "DestIP " << longToDottedIP(destIP) << endl;
	cout << "ForwardedIP " << forwardedIP << endl;

	//cout << "Longest Matching: " << prefixtree.matchingPrefix << endl;
	delete[] data;
	}
	
	return 0;

}

string longToDottedIP(long ip) {
	string returnStr = "";
	/* ref: http://stackoverflow.com/questions/2747219/how-do-i-split-up-a-long-value-32-bits-into-four-char-variables-8bits-using */
	//returnStr+= to_string(ip & 0x000000ffUL) + "." + to_string((ip & 0x0000ff00UL) >> 8) + "." + to_string((ip & 0x00ff0000UL) >> 16) + "." + to_string((ip & 0xff000000UL) >> 24);	
	returnStr+= to_string((ip & 0xff000000UL) >> 24) + "." + to_string((ip & 0x00ff0000UL) >> 16) + "." + to_string((ip & 0x0000ff00UL) >> 8) + "." + to_string(ip & 0x000000ffUL);
	return returnStr;
}

vector<string> parser(string s) {
	vector<string> parsed;
	int i = 0;
	int j = 0;
	string token = s.substr(0, s.find(" "));
	size_t pos = 0;
	string delimiter = " ";
	while ((pos = s.find(delimiter)) != s.length()+1 && parsed.size()!=3) {
		token = s.substr(0, pos);
			if (token != "" && token!="\t") {
			parsed.push_back(token);
			}
			s.erase(0, pos + (delimiter).length());
	}
	return parsed;
}


/*bool matchesPrefix(string prefix, string ipAdd) {
	
	
}
*/
long reverseLong(long num){
	long swapped = ((num>>24)&0xff) | // move byte 3 to byte 0
	((num<<8)&0xff0000) | // move byte 1 to byte 2
	((num>>8)&0xff00) | // move byte 2 to byte 1
	((num<<24)&0xff000000);
	
	return swapped;
	/* Source: http://stackoverflow.com/questions/2182002/convert-big-endian-to-little-endian-in-c-without-using-provided-func */
	
}

tableEntry bestMatch(vector<tableEntry> matchList) {
	long currLargest = reverseLong(inet_addr(matchList[0].getnetMask().c_str()));
	tableEntry currLargestEntry = matchList[0];
	
	for (int i = 0; i < matchList.size(); i++) {
		if (reverseLong(inet_addr(matchList[i].getnetMask().c_str())) > currLargest) {
			currLargest = reverseLong(inet_addr(matchList[i].getnetMask().c_str()));
			currLargestEntry = matchList[i];
		}
	}
	
	return currLargestEntry;
}

