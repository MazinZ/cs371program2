#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>
#include <fstream>

using namespace std;

string longToDottedIP(long ip);
vector<string> parser(string s);



struct line1 {
	unsigned char a;
	unsigned char b;
	unsigned char c;
	unsigned char d;
};

struct line2 {
	short a;
	unsigned char b;
	unsigned char c;
};

struct line3 {
	unsigned char a;
	unsigned char b;
	short c;
	
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



class Node
{ 
	public:
		char val; 
		Node *children[300];
		Node()
		{
			for (int i = 0; i < 300; i++)
				children[i] = NULL;
		}
};
 


/* 								Trie implementation								 */



class Trie
{ 
	private: 
		Node *root;
	public: 
		string matchingPrefix;

		Trie() 
		{ 
			root = initNode(0);
			matchingPrefix = "";
		}
 
		Node* initNode(int val) 
		{   
			Node* initNode = new Node; 
			initNode->val = val; 
			return initNode; 
		}
 
		void insert(string ipAdd) 
		{ 
			Node *curr = root; 
			for (int i = 0; i < ipAdd.length(); i++)
			{
				if (!curr->children[ipAdd[i] - 'A']) 
					curr->children[ipAdd[i] - 'A'] = initNode(ipAdd[i]);
				curr = curr->children[ipAdd[i] - 'A']; 
			}
		}
 
		void createString(Node *curr, string ipAdd, int i) 
		{ 
			if (curr) 
			{ 
				matchingPrefix += curr->val; 
				if (i < ipAdd.length()) 
					createString(curr->children[ipAdd[i] - 'A'], ipAdd, i + 1); 
			}
		}
 
		void search(string ipAdd) 
		{ 
			if (root && ipAdd.length() > 0 ) 
				createString(root->children[ipAdd[0] - 'A'], ipAdd, 1); 
		
		}
};

/* 								End trie implementation								 */















int main(int argc, char *argv[]) {
	FILE *fp;
	fp = fopen ("./ip_packets", "rb");
	//while (!feof(fp)){}
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
	short checksum = z.c; // wrong, needs htons
	long sourceIP;
	long destIP;

	fread(&sourceIP, 4, 1, fp);
	fread(&destIP, 4, 1, fp);

	
	char *data;
	data = NULL;
	data = new char[total_len-20];
	//fread(&data, total_len-20, 1, fp);
	
	
	/*    					ROUTING TABLE PARSING					*/
	ifstream routingTable;
	routingTable.open("./routing_table.txt", ifstream::in);
	string line;
	vector<tableEntry> routingEntries;
	Trie prefixtree;
	while (getline(routingTable, line))
	{
		vector<string> parsed;
		parsed = parser(line);
		tableEntry newTableEntry(parsed[0], parsed[1], parsed[2]);
		routingEntries.push_back(newTableEntry);
		prefixtree.insert(parsed[0]);
	}
	routingTable.close();
	
	
	
	/*						OUTPUT FILE 							*/
	
	
	
	
	
	
	//								TESTING PRINT FOR ROUTING TABLE                      //
	
	for (int i = 0; i < routingEntries.size(); i++){
		cout << routingEntries[i].getSourceIP() << " " << routingEntries[i].getnetMask() << " " << routingEntries[i].getnextHop() << " " << endl;
	}
	
	
	
	
	/*																*/
	/*short mynum = x.a & 0xFFFF;
	short mynum2 = (x.a & 0x0000FFFF) >> 16;
	short mynum3 = y.a & 0xFFFF;
	short mynum4 = (y.a & 0x0000FFFF) >> 16;
	short mynum5 = (z.a & 0xFFFF);
	short mynum6 = (z.a & 0x0000FFFF) >> 16;
	short mynum7 = sourceIP & 0xFFFF;
	short mynum8 = (sourceIP & 0x0000FFFF) >> 16;
	short mynum9 = destIP & 0xFFFF;
	short mynum10 = (destIP & 0x0000FFFF) >> 16;*/
	
	//if(sum1 >= 65536);
	
	
	//01000101 000000000
	//00000000 000000000
//	sourceIP = (sourceIP>>16) | (sourceIP<<16);
	//destIP = (destIP>>16) | (destIP<<16);
	sourceIP = htonl(sourceIP);
	destIP = htonl(destIP);
	
	long mynum = (x.a << 8) | (x.b);
	long mynum2 = (x.c << 8) | (x.d);
	long mynum3 = htons((y.a));
	long mynum4 = (y.b << 8) | (y.b);
	long mynum5 = (z.a << 8) | (z.b);
	long mynum6 = htons((z.c));
	long mynum7 = (sourceIP & 0xffff0000) >> 16;
	long mynum8 = (sourceIP & 0x0000ffff);
	long mynum9 = (destIP & 0xffff0000) >> 16;
	long mynum10 = (destIP & 0x0000ffff);
	


	vector<long> nums;
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

	long sum = 0;
	int j = 1;

	for (int i = 0; i < nums.size(); i+=2) {
		//cout << "NUM: " << i+1 << " " << nums[i] << endl;
		//cout << "NUM: " << j+1 << " " << nums[j] << endl;

		if (sum + nums[i] + nums[i+1] >= 65535) {
			sum += (nums[i] + nums[i+1] - 65536 + 1);
		}
		else {
			sum += nums[i] + nums[i+1];
 		}
		j+=2;
	}
		
	
	cout << "sum: " << sum << endl;
	
	//cout << "Checksum: " << ~mynum + ~mynum2 + ~mynum3 + ~mynum4 + ~mynum5 + ~mynum6 + ~mynum7 + ~mynum8 + ~mynum9 + ~mynum10  << endl;

	
	cout << version << endl;
	cout << hlen << endl;
	cout << total_len << endl;
	cout << identifier << endl;
	cout << TTL << endl;
	cout << checksum << endl;
	cout << "SourceIP " << longToDottedIP(sourceIP) << endl;
	cout << "DestIP " << longToDottedIP(destIP) << endl;
	prefixtree.search(longToDottedIP(destIP));
	cout << "Longest Matching: " << prefixtree.matchingPrefix << endl;
	
	
	
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


