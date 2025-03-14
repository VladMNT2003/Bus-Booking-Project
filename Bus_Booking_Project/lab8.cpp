#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <sstream>
#include <set>
#include <regex>
#include <ctime>

using namespace std ;

class RSAEncryption {

private:
    set<int> primes;
    int public_key;
    int private_key;
    int n;

    int calculateGCD(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    void primefiller() {
        vector<bool> sieve(250, true);
        sieve[0] = false;
        sieve[1] = false;

        for (int i = 2; i < 250; i++) {
            for (int j = i * 2; j < 250; j += i) {
                sieve[j] = false;
            }
        }

        for (int i = 0; i < sieve.size(); i++) {
            if (sieve[i])
                primes.insert(i);
        }
    }

    int pickrandomprime() {
        int k = rand() % primes.size();
        auto it = primes.begin();
        while (k--)
            it++;
        int ret = *it;
        primes.erase(it);
        return ret;
    }

    void setkeys() {
        int prime1 = pickrandomprime();
        int prime2 = pickrandomprime();

        n = prime1 * prime2;
        int fi = (prime1 - 1) * (prime2 - 1);
        int e = 2;

        while (1) {
            if (calculateGCD(e, fi) == 1)
                break;
            e++;
        }

        public_key = e;
        int d = 2;

        while (1) {
            if ((d * e) % fi == 1)
                break;
            d++;
        }

        private_key = d;
    }

    long long int encrypt(double message) {
        int e = public_key;
        long long int encrypted_text = 1;

        while (e--) {
            encrypted_text *= message;
            encrypted_text %= n;
        }

        return encrypted_text;
    }

    long long int decrypt(int encrypted_text) {
        int d = private_key;
        long long int decrypted = 1;

        while (d--) {
            decrypted *= encrypted_text;
            decrypted %= n;
        }

        return decrypted;
    }

public:
    vector<int> encoder(string message) {
        vector<int> form;

        for (auto &letter : message)
            form.push_back(encrypt((int)letter));

        return form;
    }

    string decoder(vector<int> encoded) {
        string s;

        for (auto &num : encoded)
            s += decrypt(num);

        return s;
    }

    void performEncryption(string message) {
        primefiller();
        setkeys();


        
        vector<int> coded = encoder(message);
        ofstream fout("parola.csv" , ios::app) ;
        for(int i = 0 ; i < coded.size() ; i++){
            fout << coded[i] << "," ;
        }
        fout<<endl ;
        fout.close() ;

        // cout << "Initial message:\n" << message << endl;
        // cout << "\n\nThe encoded message (encrypted by public key)\n";
        
        // for (auto &p : coded)
        //     cout << p;

        // cout << "\n\nThe decoded message (decrypted by private key)\n";
        // cout << decoder(coded) << endl;
    }
};
// Clasa pentru gestionarea fișierelor CSV

class ValidareData {
public:
    bool executaValidare(string input) {
        int year, month, day;
        if (sscanf(input.c_str(), "%d-%d-%d", &year, &month, &day) != 3 || !isValidDateComponents(year, month, day)) {
            return false;
        }

        if (isPastDate(input)) {
            return false ;
        } else {
            return true;
        }
    }

    bool isValidDateFormat(const string &input) {
        regex datePattern("\\d{4}-\\d{2}-\\d{2}");
        return regex_match(input, datePattern);
    }

    bool isValidDateComponents(int year, int month, int day) {
        return (year >= 0 && month >= 1 && month <= 12 && day >= 1 && day <= 31);
    }

    bool isPastDate(const string &input) {
        time_t currentTime = time(nullptr);
        tm *localTime = localtime(&currentTime);

        tm enteredDate = {};
        if (sscanf(input.c_str(), "%d-%d-%d", &enteredDate.tm_year, &enteredDate.tm_mon, &enteredDate.tm_mday) != 3) {
            return false;
        }

        enteredDate.tm_year -= 1900;
        enteredDate.tm_mon -= 1;

        if (!isValidDateComponents(enteredDate.tm_year, enteredDate.tm_mon + 1, enteredDate.tm_mday)) {
            //cout << "Data introdusa nu este valida.\n";
            return false;
        }

        if (enteredDate.tm_year < localTime->tm_year ||
            (enteredDate.tm_year == localTime->tm_year && enteredDate.tm_mon < localTime->tm_mon) ||
            (enteredDate.tm_year == localTime->tm_year && enteredDate.tm_mon == localTime->tm_mon && enteredDate.tm_mday < localTime->tm_mday)) {
            return true;
        } else {
            return false;
        }
    }
};


class Operator {
    public:

    string username;
    string password;  // Notă: Parola ar trebui criptată într-o implementare reală
    
    void login(){
        cout << "Introduceti username: ";
        getline(cin, username);
        cout << "Introduceti parola: ";
        getline(cin, password);    
    }

    // Metoda pentru verificarea credențialelor (poate fi extinsă pentru a utiliza criptarea)
    void verifyCredentials() {
        fstream fin ;
        fin.open("baza_de_date_utilizatori.csv", ios::in) ;
        vector<string> row; 
        vector<vector<string>> data;
        string line, word, temp;
        int nr_linii = 0 ;
        RSAEncryption rsa;
        while (getline(fin, line)) { 
  
        row.clear(); 
  
        // read an entire row and 
        // store it in a string variable 'line'  
  
        // used for breaking words 
        stringstream s(line); 
    
        // read every column data of a row and 
        // store it in a string variable, 'word' 

        
        while (getline(s, word, ',')) { 
  
            // add all the column data 
            // of a row to a vector 
            row.push_back(word); 
        }
        data.push_back(row);
        nr_linii++ ;
        
        } 
        for(int i = 0 ; i < nr_linii ; i++){
            if(data[i][0] == username && data[i][1] == password){
                cout << "Autentificare reusita!" << endl;
                rsa.performEncryption(password);
                break ;
            } else if (i == nr_linii - 1){
                cout << "Autentificare esuata!" << endl;
                exit(0) ;
            }
        }
        
        
    }
 
    // Metodă pentru adăugarea unei curse noi
    void addCursa() {
        string oras_plecare, destinatia, data, ora;
        double pret;
        ValidareData validare ;

         while (true) {
        try {
            // Citirea detaliilor cursei de la utilizator
            cout << "Introduceti orasul de plecare: ";
            getline(cin, oras_plecare);
            cout << "Introduceti destinatia: ";
            getline(cin, destinatia);
            cout << "Introduceti data (format YYYY-MM-DD): ";
            getline(cin, data);
            
            // Validare data
            if (!validare.executaValidare(data)) {
                throw invalid_argument(""); // Aruncă excepție vidă pentru a reapeleza funcția
            }

            break; // Ieșiți din buclă dacă data este validă
        } catch (const invalid_argument&) {
            cout << "Data introdusa nu este valida. Va rugam sa reintroduceti datele.\n";
        }
    }

    // Restul codului rămâne neschimbat
    
    cout << "Introduceti ora (format HH:MM): ";
    getline(cin, ora);
    cout << "Introduceti pretul: ";
    cin >> pret;
    cin.ignore(); // Curăță buffer-ul după citirea lui 'pret'

    // Deschiderea fișierului și adăugarea cursei
    ofstream file("curse.csv", ios::app); // Deschide fișierul în modul append
    if (file.is_open()) {
        file << oras_plecare << "," << destinatia << "," << data << "," << ora << "," << pret << "\n";
        file.close();
        cout << "Cursa adaugata cu succes!" << endl;
    } else {
        cout << "Nu s-a putut deschide fisierul pentru scriere." << endl;
    }
    }


    // Metodă pentru ștergerea unei curse
    void deleteCursa() {
        string oras_plecare, destinatia, data, ora;
        double pret;
        int counter1 = 0;
        int counter2 = 0;
        // Citirea detaliilor cursei de la utilizator
        cout<< "Introduceti orasul de plecare: " ;
        getline(cin, oras_plecare);
        cout << "Introduceti destinatia: ";
        getline(cin, destinatia);
        cout << "Introduceti data (format YYYY-MM-DD): ";
        getline(cin, data);
        cout << "Introduceti ora (format HH:MM): ";
        getline(cin, ora);

        // Deschiderea fișierului și ștergerea cursei
        ifstream fin("curse.csv");
        ofstream temp("temp.csv");
        if (fin.is_open() && temp.is_open()) {
            string line;
            while (getline(fin, line)) {
                stringstream ss(line);
                string oras_plecare_temp, destinatia_temp, data_temp, ora_temp, pret_temp;
                getline(ss, oras_plecare_temp, ',');
                getline(ss, destinatia_temp, ',');
                getline(ss, data_temp, ',');
                getline(ss, ora_temp, ',');
                getline(ss, pret_temp, ',');
                if (oras_plecare_temp != oras_plecare || destinatia_temp != destinatia || data_temp != data || ora_temp != ora) {
                    temp << line << "\n";
                    counter2++;
                }
                counter1++;
            }
            fin.close();
            temp.close();
            remove("curse.csv");
            rename("temp.csv", "curse.csv");
            if( counter1 ==  counter2){
                cout << "Cursa nu a fost gasita!" << endl;
            } else {
                cout << "Cursa stearsa cu succes!" << endl;
            }
        } else {
            cout << "Nu s-a putut deschide fisierul pentru scriere." << endl;
        }
        
    }

    // Alte metode specifice operatorului...
};

// Clasa pentru gestionarea utilizatorilor
class Utilizator : public Operator {
    public:

    void createAccount() {
        fstream fout ;
        fout.open("baza_de_date_utilizatori.csv" , ios::app) ;

        cout << "Introduceti un nou username: ";
        getline(cin, username);
        cout << "Introduceti parola noului cont: ";
        getline(cin, password);
        cout << "Contul a fost creat cu succes!" << endl;

        fout<<username<<","<<password<<endl ;

        fout.close() ;
    }

};

int main() {
    int value ;
    char valoare ;
    char val ;
    Operator op;
    Utilizator ut;
    RSAEncryption rsa;
    ValidareData validator;
    cout << "Bine ati venit in aplicatia mea!" << endl;
    cout << "Alegeti una din urmatoarele optiuni:" << endl;
    cout << "1: Autentificare" << endl;
    cout << "2: Creare cont" << endl;
    cout << "Orice alta tasta: Iesire" << endl;
    cin >> value ;
    cin.ignore() ;

    switch (value){
        case 1:
            op.login();
            op.verifyCredentials();
            cout << "Doriti sa adaugati o cursa? (D/N)" << endl;
                cin >> val ;
                cin.ignore() ;
                if(val == 'D'){
                    op.addCursa() ;
                } else if(val == 'N'){
                    cout<< "Doriti sa stergeti o cursa? (D/N)"<<endl ;
                        cin >> val ;
                        cin.ignore() ;
                        if(val == 'D'){
                            op.deleteCursa() ;
                            cout<<"Cursa a fost stearsa cu succes!" ;
                        }
                        else{
                            cout<<"Ati parasit aplicatia!" ;
                            exit(0) ;
                        }
                }
            break;
        case 2:
            ut.createAccount();
            cout << "Doriti sa va autentificati? (D/N) " << endl;
            cin >> valoare ;
            cin.ignore() ;
            if(valoare == 'D'){
                op.login();
                op.verifyCredentials();
                cout << "Doriti sa adaugati o cursa? " << endl;
                cin >> val ;
                if(val == 'D'){
                    op.addCursa() ;
                } else {
                    cout<< "Doriti sa stergeti o cursa? (D/N)"<<endl ;
                        cin >> val ;
                        cin.ignore() ;
                        if(val == 'D'){
                            op.deleteCursa() ;
                            cout<<"Cursa a fost stearsa cu succes!" ;
                        }
                        else{
                            cout<<"Ati parasit aplicatia!" ;
                            exit(0) ;
                        }

                }
            } else {
                cout<<"Ati parasit aplicatia!" ;
                exit(0) ;
            }
            break;
        default:
            cout << "Ati parasit aplicatia! " << endl;
            break;
    }

    
    return 0;

    
}
