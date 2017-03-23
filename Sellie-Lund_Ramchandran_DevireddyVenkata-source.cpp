//------------------------------------------------------------------------//
//------------------------------:CODED BY:--------------------------------//
//------------------------------------------------------------------------//
//--------------------------------TSL325----------------------------------//
//------------------------------------------------------------------------//
//--------------------------------SDV267----------------------------------//
//------------------------------------------------------------------------//
//--------------------------------AR4996----------------------------------//
//------------------------------------------------------------------------//


//------------------------------------------------------------------------//
//---------------------------POINT OF ENTRY-------------------------------//
//------------------------------------------------------------------------//
#include <stdio.h>
#include <vector>
#include <chrono>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <thread>
//------------------------------------------------------------------------//
//----------------GLOBAL VARIABLES, TYPE DEFS, FUNCTION DEF---------------//
//------------------------------------------------------------------------//
std::vector<std::string> PossibleWords;
using namespace std;

typedef struct __key {
	int key[106];//Key index
	int layer[106];
} key;
int plaintext_test(vector <int> ciphertext, string plain[5]);//PART I definition
int load_dictionary(const char * wordname, std::vector<std::string> &dict_to_load);//Dictionary load
int attack(std::vector<int> ciphertext, std::vector<std::string> wordlist);//PART II definition
int attack_helper(std::vector<int> & ciphertext, std::vector<std::string> & wordlist, key*k, int layer, int scanpos, std::string tryword);
int valid_key(key*k, int layer);
int time_out();
bool endNow = false;
std::vector<std::string> Longest;
int longestLen = 0;
string plaintext[5], pl;
ifstream fd1("plt.txt");
//------------------------------------------------------------------------//
//---------------------------PART I CRYTANALYSIS--------------------------//
//------------------------------------------------------------------------//
int plaintext_test(vector <int> ciphertext, string plain[5])
{
	int zop = 0, flag1 = 1, flag2 = 1;
	for (zop = 0; zop < 5; zop++)//Iterate through the array of strings.
	{
		int p, pos, count_b = 0, count_x = 0, i = 0;
		flag1 = 1;
		flag2 = 1;
		vector<int> vect2;//The Letter B position Vector
		vector<int> vect2_x;//The Letter X position Vector
		string bamboo;
		bamboo = plain[zop];//Store each string
		for (int j = 0; j < bamboo.size(); j++)//Iterate through each string
		{
			if (bamboo[j] == 'b')//Find Position of B
			{
				p = 0;
				p = j + 1;
				vect2.push_back(p);//Push position of B in vector
				count_b += 1;
			}
			else if (bamboo[j] == 'x')//Find Position of X
			{
				p = 0;
				p = j + 1;
				vect2_x.push_back(p);//Push position of X in vector
				count_x += 1;
			}
		}
		for (int j = 0; j < count_b - 1; j++)
		{
			int l1 = vect2.at(j);
			int l2 = vect2.at(j + 1);
			if (ciphertext.at(l1 - 1) != ciphertext.at(l2 - 1))//Compare positions of B to cipher text.
			{
				flag1 = 0;//Flag1 down
			}
		}

		for (int j = 0; j < count_x - 1; j++)
		{
			int l1 = vect2_x.at(j);
			int l2 = vect2_x.at(j + 1);
			if (ciphertext.at(l1 - 1) != ciphertext.at(l2 - 1))//Compare positions of X to cipher text.
			{
				flag2 = 0;//Flag2 down
			}
		}

		if (flag1 == 1 && flag2 == 1)// If positions match, Print the plaintext out.
		{
			cout << plaintext[zop];//Print plaintext
			cout << "\n";
			break;
		}
	}
	if (flag1 == 0 && flag2 == 0 && zop == 5)// Else Call Decryption Phase II
	{
		int ret = attack(ciphertext, PossibleWords);
		if (ret == 2) {
			std::cout << "Longest found pattern: " << std::endl;
		}
		for (int i = Longest.size() - 1; i >= 0; i--) {
			std::cout << Longest[i] << " ";
		}
		std::cout << std::endl;
	}
	return 0;
}
//------------------------------------------------------------------------//
//---------------------------Main Function--------------------------------//
//------------------------------------------------------------------------//
int main(int argc, char**argv)
{
	int cpn=0;
	load_dictionary("english_words.txt", PossibleWords);//load dictionary
	string fn, line;
	ifstream fd;
	cout << "\nWelcome to the crypto breaker!\n";
	cout << "\n------------------------------\n";
	cout << "\nEnter the name of the file with extension to be cracked. Make sure each ciphertext is seperated by a new line character:\n";
	getline(cin, fn);//get ciphertext file name.

	// start timer!
	std::thread timer(time_out);


	fd.open(fn.c_str());//open file
	for (int zop = 0; zop<5; zop++)//load plaintext from plt.txt
	{
		getline(fd1, pl);
		plaintext[zop] = pl;
	}
	fd1.close();
	while (fd.good())
	{
		getline(fd, line);
		vector<int> vect;
		stringstream ss(line);
		int i = 0;
		while (ss >> i)
		{
			vect.push_back(i);
			if (ss.peek() == ',' | ss.peek() == '\n')
				ss.ignore();
		}
		cpn+=1;
		std::cout<<"\nSolution "<<cpn<<":\n";
		plaintext_test(vect, plaintext);
	}
	fd.close();
	return 0;
	system("pause");
	exit(1);
}
//------------------------------------------------------------------------//
//------------------------DECRYPTION PHASE II-----------------------------//
//------------------------------------------------------------------------//

// Loads a file of words into a vector<string>
// near instant (supposedly)
int load_dictionary(const char* wordname, std::vector<std::string> &dict_to_load) {
	FILE * dictionary = fopen(wordname, "r");
	char buffer[100];
	while (fgets(buffer, 99, dictionary) != 0) {
		std::string curr = std::string(buffer);
		curr.erase(curr.find_last_not_of(" \n\r\t") + 1);
		dict_to_load.push_back(curr);
	}
	return 0;
}

int valid_key(key*k, int layer) {
	int radix[27];
	memset(radix, 0, sizeof(int) * 27);
	const int max[] = { 19,7,1,2,4,10,2,2,5,6,1,1,3,2,6,6,2,1,5,5,7,2,1,2,1,2,1 };
	for (int i = 0; i < 106; i++) {
		if (k->layer[i]>layer) continue;
		else if (k->key[i] == 0) continue;
		else if (k->key[i] == 32) radix[0]++; // if space, handle separately
		else if (k->key[i] < 0x60 || k->key[i] > 122) { std::cout << "Warning, Nonprinting character:" << k->key[i] << " detected in key" << std::endl; return 0; }
		else radix[k->key[i] - 0x60]++;  // subtract 60, so we align 'a' with index 1 ('a'==0x61)
	}
	for (int i = 0; i < 27; i++) {
		if (radix[i]>max[i]) return 0;
	}
	return 1;
}

// attack a given ciphertext and wordlist
int attack(std::vector<int> ciphertext, std::vector<std::string> wordlist) {
	// generate a new key trial
	key * k = (key*)malloc(sizeof(key));
	// make sure it's zero
	memset(k, 0, sizeof(key));
	// for every word in the word list
	for (int i = 0; i < wordlist.size(); i++) {
		// recursively call
		int ret = attack_helper(ciphertext, wordlist, k, 0, 0, wordlist[i]);
		if (ret==1) {
			//std::cout << wordlist[i];
			free(k);
			Longest.push_back(wordlist[i]);
			return 1;
		}
		if (endNow) { // timeout
			free(k);
			Longest.push_back(wordlist[i]);
			return 2;//  we didn't succeed (otherwise we would have returned above
		}
	}


	free(k);
	exit(0);
}
// recursive helper for attack
int attack_helper(std::vector<int> & ciphertext, std::vector<std::string> & wordlist, key*k, int layer, int scanpos, std::string tryword) {
	// check to see if we have found a longer string than before.
	int rval = 0;
	if (scanpos > longestLen) {
		rval = 2;
		longestLen = scanpos;
		// reset longest. ( to record this one )
		Longest.clear();
	}
	// rval now indicates if this is longer than before.





	// put it into key with layer
	for (int i = 0; i < tryword.size(); i++) {
		int cph = ciphertext[scanpos];
		if (k->key[cph] != tryword[i] && k->layer[cph] < layer) return rval; // failed, invalid key
																			 // else
		k->key[cph] = tryword[i]; // insert it.
		k->layer[cph] = min(layer, k->layer[cph]); // preserve lower layers.
		if (scanpos >= ciphertext.size()) { // base case
			Longest.push_back(tryword.substr(0, i)); // append end to "longest"
			return 1;
		}
		scanpos++;
	}
	// Add a space at the end of the word
	int cph = ciphertext[scanpos];
	if (k->key[cph] != ' ' && k->layer[cph] < layer) return rval; // failed, invalid key
																  // else
	k->key[cph] = ' ';
	k->layer[cph] = min(layer, k->layer[cph]);
	scanpos++;

	if (!valid_key(k,layer)) return rval; // key was built, but failed validation





	bool lngr = false; // if we have found a longer substring
	for (int i = 0; i < wordlist.size() && !endNow; i++) { // while we have words to try, and the timeout hasn't expired.
														   // recursively call
		int ret = attack_helper(ciphertext, wordlist, k, layer + 1, scanpos, wordlist[i]);
		if (ret == 1) { // return code 1 indicates sucess
			Longest.push_back(tryword); // by definition, a success is the longest substring.
			return 1;
		}
		else if (ret == 2) { // return code 2 indicates a longer substring.
			lngr = true; // say we have found a longer substring
		}
	}

	// save longest.
	if (lngr) {
		Longest.push_back(tryword);
		return 2;
	}
	return rval;
}

/*
sleep for 2 minutes, handle timout
*/
int time_out()
{
	std::this_thread::sleep_for(std::chrono::seconds(2));
	std::cout << "Timeout Detected" << std::endl;
	endNow = true;
	return 0;
}
