#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ostream>

using namespace std;

string longToDottedIP(long ip);
vector<string> parser(string s);
bool matchesPrefix(string prefix, string ipAdd);
long reverseLong(long num);
bool validChecksum(vector<unsigned long> wordList);
unsigned long recalculateChecksum(vector<unsigned long> wordList, unsigned long newTTLword);

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



int main(int argc, char *argv[]) {
	
	int packetCounter = 1;
	//ofstream outputFile (“ip_packets_out”,ios::binary);
  	 ofstream ofs ( "ip_packets_out", ios_base::binary );
	
	/*    					ROUTING TABLE PARSING					*/

	ifstream routingTable;
	routingTable.open("./routing_table.txt", ifstream::in);
	string line;
	vector<tableEntry> routingEntries;
	
	
	while (getline(routingTable, line))
	{
		
		vector<string> parsed;
		parsed = parser(line);
		tableEntry newTableEntry(parsed[0], parsed[1], parsed[2]);
		routingEntries.push_back(newTableEntry);
	}
	routingTable.close();
	
	FILE *fp;
	fp = fopen ("./ip_packets", "rb");
	while (true){
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


		if( feof(fp) ){
	   		break;
		}	
	
	
	
		bool matchFound = false;	
		string forwardedIP = "";
		vector<tableEntry> matchList;
	
		for (int i = 0; i <routingEntries.size()-1; i++) {
	
			long testValue = reverseLong(inet_addr(routingEntries[i].getSourceIP().c_str())) ^ destIP & reverseLong(inet_addr(routingEntries[i].getnetMask().c_str()));
		
		
			if (testValue == 0){
				matchFound = true;
				matchList.push_back(routingEntries[i]);
				forwardedIP = routingEntries[i].getnextHop();
			}
		
	
		}
		if (matchFound) {
			forwardedIP = bestMatch(matchList).getnextHop();
		}
		else {
		forwardedIP = routingEntries[routingEntries.size()-1].getSourceIP();
		}
	
	
	/*						OUTPUT FILE 							*/
	


		unsigned long word1 = (x.a << 8) | (x.b);
		unsigned long word2 = (x.c << 8) | (x.d);
		unsigned long word3 = htons((y.a));
		unsigned long word4 = (y.b << 8) | (y.b);
		unsigned long word5 = (z.a << 8) | (z.b);
		unsigned long long1 = (z.a - 1) | (z.b);
	/*	unsigned long test = TTL;
cout <<"Z: " << test << endl;*/

		unsigned long word6 = htons((z.c));
		unsigned long word7 = (sourceIP & 0xffff0000) >> 16;
		unsigned long word8 = (sourceIP & 0x0000ffff);
		unsigned long word9 = (destIP & 0xffff0000) >> 16;
		unsigned long word10 = (destIP & 0x0000ffff);
		


		vector<unsigned long> wordList;
		wordList.push_back(word1);
		wordList.push_back(word2);
		wordList.push_back(word3);
		wordList.push_back(word4);
		wordList.push_back(word5);
		wordList.push_back(word6);
		wordList.push_back(word7);
		wordList.push_back(word8);
		wordList.push_back(word9);
		wordList.push_back(word10);
			
		if (TTL - 1 == 0 || TTL == 0) {
			cout << "Packet #" << packetCounter << ": Dropped because TTL becomes 0." << endl;
			packetCounter+=1;
			continue;
		}

		if (!validChecksum(wordList)) {
			cout << "Packet #" << packetCounter << ": Dropped because of incorrect checksum." << endl;
			packetCounter+=1;

			continue;
		}
		cout << "Packet #" << packetCounter << ": Forwarded to " << forwardedIP << endl;
		
		packetCounter+=1;
		unsigned short newChecksum = recalculateChecksum(wordList, (z.a - 1) << 8 | (z.b));
		cout << newChecksum<< endl;
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


bool validChecksum(vector<unsigned long> wordList) {
	unsigned long sum = 0;

	for (int i = 0; i < wordList.size(); i+=1) {
	
		if (sum + wordList[i] >= 65535) {
			sum += (wordList[i] - 65536 + 1);
		}
		else {
			sum += wordList[i];
 		}
	}
	
	if (sum == 0) {
		return true;
	}
	else {
		return false;
	}
}

unsigned long recalculateChecksum(vector<unsigned long> wordList, unsigned long newTTLword) {
	unsigned long sum = 0;
	wordList[4] = newTTLword;
	
	//cout << "TEST " << newTTLword << endl;
	//cout << newTTLword << endl;
	for (int i = 0; i < wordList.size(); i+=1) {
			//cout << " i = " << i+1 << "WORDLIST: " << wordList[i] << endl;
			if (i == 5){
				continue;
				
			}
			
			if (sum + wordList[i] >= 65535) {
				sum += (wordList[i] - 65536 + 1);
			}
			else {
				sum += wordList[i];
	 		}
	
		}
		
		return ~sum;
	
}
