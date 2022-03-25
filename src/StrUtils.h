#ifndef ANSIUTILSH
#define ANSIUTILSH
//---------------------------------------------------------------------------

    /* ##########################################################################

    Date:            16/Oct/2013
    Developed by:    Juan Carlos García Vázquez.
    Personal E-Mail: gavajc@gmail.com

    This library have many utility functions for work with AnsiStrings with
    codification ISO-8859-1 or with UNICODE with UTF-16 Windows and UTF-32 UNIX.

    Some functions for:
                        Check if a template is a string object.
                        Tolower and toupper Special Chars.
                        Erase chars from string.
                        Tokenize string.
                        Tolower or toupper a string.
                        Get substrings.
                        Convert number to string.
                        Trim a String Left and Rigth.
                        Compare 2 strings case-insensitive.
                        Check if a string is valid number bases (2,8,10,16).
                        Find char foward and backward in string.

    ####################################################################### */
//---------------------------------------------------------------------------

#include <set>           // # Standard C/C++ Librarys.
#include <ctime>
#include <cctype>
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <sstream>
#include <typeinfo>
#include <stdexcept>
#include <algorithm>
#include <sys/stat.h>

using namespace std;

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
    #define OP_SLASH '\\'
#else
    #define OP_SLASH '/'
#endif
//---------------------------------------------------------------------------

class AnsiStr 
{
     public:
    //---------------------------------------------------------------------------
    /*! ############ Check for templates if a value is Ansi Object ##############

        Function name: checkString.
        Functionality: Know if a template object is a String.
        Explication:
                        Function used for retrieve infromation about
                        templates params. Special for know if the param
                        is a string object from STL. Or if is an AnsiString
                        from VCL Borland library.

        ####################################################################### */

    template <typename T>
    static short checkString(T v)
    {
        string typeName = typeid(v).name();

        if ((typeid(string) == typeid(v)) || (typeid(wstring) == typeid(v)))
            return 0;
        if (typeName.find("AnsiString") != string::npos)
            return 1;
        if (typeName.find("UnicodeString") != string::npos)
            return 1;		

        return -1;
    }
    //---------------------------------------------------------------------------
    /*! ########################### Tolower any char ############################

        Function Name: charTolower
        Functionality: Converts any char c to tolower case.
        Explication:
                        Convert any ASCII And Extended char to tolower case.
                        Including special chars as Á;É;Í etc...

        ###################################################################### */

    static char charTolower(char c)
    {
        switch(c) {
            case 'Á': return 'á';
            case 'É': return 'é';
            case 'Í': return 'í';
            case 'Ó': return 'ó';
            case 'Ú': return 'ú';
            case 'Ü': return 'ü';
            case 'Ñ': return 'ñ';
            default: return (char) tolower(c);
        }
    }
    //---------------------------------------------------------------------------
    /*! ########################### Tolower any char ############################

        Function Name: charToupper
        Functionality: Converts any char c to toupper case.
        Explication:
                        Convert any ASCII And Extended char to toupper case.
                        Including special chars as Á;É;Í etc...

        ###################################################################### */

    static char charToupper(char c)
    {
        switch(c) {
            case 'Á': return 'á';
            case 'É': return 'é';
            case 'Í': return 'í';
            case 'Ó': return 'ó';
            case 'Ú': return 'ú';
            case 'Ü': return 'ü';
            case 'Ñ': return 'ñ';
            default: return (char) toupper(c);
        }
    }
    //---------------------------------------------------------------------------
    /*! ########################## Tolower a string #############################

        Function Name: strTolower
        Functionality: Converts any STL string str to tolower case.
        Explication:
                        Overloaded. Convert any ASCII And Extended char
                        in the STL string to tolower case. Including special
                        chars as Á;É;Í etc...
        Warning:
                        If the pointer param is NULL, then the function do
                        nothing and return a NULL pointer.

        ###################################################################### */

    static string *strTolower(string *str)
    {
        if(str == NULL) return NULL;
        transform(str->begin(),str->end(),str->begin(),(char (*)(char)) :: AnsiStr::charTolower);
        return str;
    }
    //---------------------------------------------------------------------------
    /*! ########################## Tolower a char * #############################

            Function Name: strTolower
            Functionality: Converts any char *str to tolower case.
            Explication:
                                       Overloaded. Convert any ASCII And Extended char
                                       in the char * to tolower case. Including special
                                       chars as Á;É;Í etc...
            Warning:
                                       If the pointer param is NULL, then the function do
                                       nothing and return a NULL pointer.

                                       If the parameter is a temp object. The result will be
                                       wrong pointer to memory. Example strTolower("MIVALOR");

            ###################################################################### */

    static char *strTolower(char *Str)
    {
            if(Str == NULL) return NULL;
            for (unsigned i = 0; Str[i] != 0; i++)
                 Str[i] = charTolower(Str[i]);

            return Str;
    }
    //---------------------------------------------------------------------------
    /*! ########################## Touppere a string #############################

        Function Name: strToupper
        Functionality: Converts any STL string str to toupper case.
        Explication:
                        Overloaded. Convert any ASCII And Extended char
                        in the STL string to toupper case. Including special
                        chars as Á;É;Í etc...
        Warning:
                        If the pointer param is NULL, then the function do
                        nothing and return a NULL pointer.

        ###################################################################### */

    static string *strToupper(string *str)
    {
        if(str == NULL) return NULL;
        transform(str->begin(),str->end(),str->begin(),(char (*)(char)) :: AnsiStr::charToupper);
        return str;
    }
    //---------------------------------------------------------------------------
    /*! ########################## Toupper a char * #############################

            Function Name: strTolower
            Functionality: Converts any char *str to tolower case.
            Explication:
                           Overloaded. Convert any ASCII And Extended char
                           in the char * to toupper case. Including special
                           chars as Á;É;Í etc...
            Warning:
                           If the pointer param is NULL, then the function do
                           nothing and return a NULL pointer.

                           If the parameter is a temp object. The result will be
                           wrong pointer to memory. Example strTolower("MIVALOR");

            ###################################################################### */

    static char *strToupper(char *Str)
    {
            if(Str == NULL) return NULL;
            for (unsigned i = 0; Str[i] != 0; i++)
                 Str[i] = AnsiStr::charToupper(Str[i]);

            return Str;
    }
    //---------------------------------------------------------------------------
    /*! ########################## Trim a String ################################

        Function Name: strTrim
        Functionality: Trims rigth and left a STL string str.
        Explication:
                        Overloaded. Erase the extra spaces in the STL string.
                        The trim is apply for left and rigth.
        Warning:
                        If the pointer param is NULL, then the function do
                        nothing and return a NULL pointer.

        ###################################################################### */

    static string *strTrim(string *str)
    {
        int pi=0;
        char c;

        if(str == NULL) return NULL;
        while ((pi =str->find(' ',pi)) != -1)
        {
                c = str->c_str()[pi+1];
                if (c == ' ' || c == 0 || pi == 0)
                    str->erase(pi,1);
                else pi++;
        }

        return str;
    }	
    //---------------------------------------------------------------------------
    /*! ##################### Find char in char * backward ######################

        Function Name: charRFind
        Functionality: Find a char in a string. Start at the end of the string.
        Explication:
                        Find char in a string pointed for c from the end to
                        begin of the string. If find the char then
                        return the pos in the string for the char. Else return -1.
        Warning:
                        If param  str is a invalid pointer (NULL) then
                        throws a char * Exception.

                        For AnsiString the counter starts in 1. Then when
                        the result is retrieve add 1 to this result.

        ###################################################################### */

    static int charRFind(const char *str, const char c)
    {
        int i;

        if (str == NULL)
            throw std::logic_error("The string param is invalid pointer.");

        for (i = strlen(str)-1; i >= 0 && str[i] != c; i--);

        return i;
    }

    //---------------------------------------------------------------------------
    /*! ##################### Find char in char * backward ######################

        Function Name: findChars
        Functionality: Find a group of chars in a string.
        Explication:
                        Find a group of chrs in a string pointed by chrs
                        If find a char in the string, then return the position of
                        the first occurrence if not find any char then return -1.
        Warning:
                        If param  str is a invalid pointer (NULL) then
                        return -1.

                        For AnsiString the counter starts in 1. Then when
                        the result is retrieve add 1 to this result.

        ###################################################################### */

    static int findChars(const char *str, const char *chrs)
    {
        int i;
        const char *p;

        if (str == NULL || chrs == NULL)
            return -1;

        for (i = 0 ; str[i] != '\0'; i++)
        {
             for (p = chrs; *p != 0; p++)
             {
                  if (*p == str[i])
                      return i;
             }
        }

        return -1;
    }

    //---------------------------------------------------------------------------
    /*! ################# Erase all chars in string by Chars ####################

        Function Name: eraseChars
        Functionality: Delete all chars in the string STL str that have in Chars.
        Explication:
                        Overloaded. Erase all chars in the string STL when
                        the char is in the string Chars.
        Warning:
                        If the pointer is NULL, then the function do nothing
                        and return.
                        
                        Future for VCL Builder C++

        ###################################################################### */

    static void eraseChars(string *str, const char *Chars)
    {
        if(str == NULL) return;
        for (unsigned i = 0; i < str->length(); i++)
        {
                for (unsigned j = 0; Chars[j] != 0; j++)
                {
                    if (str->at(i) == Chars[j]) {
                        str->erase(i,1);
                        i--;
                        break;
                    }
                }
        }
    }

    //---------------------------------------------------------------------------
    /*! ################# Erase all chars in char * by Chars ####################

        Function Name: eraseChars
        Functionality: Delete all chars in the char * str that have in Chars.
        Explication:
                        Overloaded. Erase all chars in the char * when
                        the char is in the char * Chars.
        Warning:
                        If the pointer is NULL, then the function do nothing
                        and return.

        ###################################################################### */

    static void eraseChars(char *str, const char *Chars)
    {
        if(str == NULL) return;
        for (unsigned i = 0; str[i] != 0; i++)
        {
                for (unsigned j = 0; Chars[j] != 0; j++)
                {
                    if (str[i] == Chars[j])
                    {
                        for (unsigned k = i; str[k] != 0; k++)
                            str[k] = str[k+1];
                        i--;
                        break;
                    }
                }
        }
    }
    //---------------------------------------------------------------------------
    /*! ########### Replace a selected char in string *str with other ###########

        Function Name: replaceChar
        Functionality: replace all oChar in string *str with rChar.
        Explication:
                    Overloaded. Replace all chars in the string *str when
                    the char is oChar with the new char rChar.
        Warning:
                    If the pointer is NULL, then the function do nothing
                    and return.

        ###################################################################### */

    template <typename T> static
    T * replaceChar(T *str, char oChar, char rChar)
    {
        if (str == NULL) return str;

        for (int i = 0, j = checkString(*str); str->c_str()[i]; i++)
            if (str->c_str()[i] == oChar)
                str->operator [](i+j) = rChar;

        return str;
    }
    //---------------------------------------------------------------------------
    /*! ############ Replace a selected char in char *str with other ############

        Function Name: replaceChar
        Functionality: replace all oChar in char *str with rChar.
        Explication:
                    Overloaded. Replace all chars in the char *str when
                    the char is oChar with the new char rChar.
        Warning:
                    If the pointer is NULL, then the function do nothing
                    and return.

        ###################################################################### */

    static char * replaceChar(char *str, char oChar, char rChar)
    {
        if (str == NULL) return str;

        for (char *ptr = str; *ptr; ptr++)
            if (*ptr == oChar) 
                *ptr = rChar;

        return str;
    }
    //---------------------------------------------------------------------------
    /*! ######################## Compare two strings ############################

        Function Name: strCmp
        Functionality: Compare 2 string case-insensitive.
        Explication:
                    Compare 2 const char * strings without case-sensitive
                    and return:
                    1 if the first is greater than second.
                    0 if both strings are the same.
                    -1 if the first is less than second.
        Warning:
                    If any pointer param or both are NULL, then the function
                    do nothing and throws a char * Exception.

        ###################################################################### */

    static short strCmp(const char *s1, const char *s2)
    {
        if (s1 == NULL || s2 == NULL)
            throw "One or Both parameters are bad pointer.";

        do
        {
        if (charTolower(*s1)>charTolower(*s2)) return 1;
        if (charTolower(*s1)<charTolower(*s2)) return -1;
        s1++; s2++;
        }while (*s1 != 0 || *s2 != 0);

        return 0;
    }
    //---------------------------------------------------------------------------
    /*! ####################### Convert a number to string ######################

        Function Name: numToStr
        Functionality: Converts a number to String.
        Explication:
                        Converts any  C/C++ number to string object. The
                        object can be STL string. The converted value as
                        string is returned.
        Warning:
                        If the T template is invalid the return value is a
                        NULL string.

                        __int64 for Windows systems and long long int for
                        UNIX systems.

        ###################################################################### */

    template <typename T>
    static string numToStr(T n)
    {
        stringstream ss;
        string typeName = typeid(n).name();

        if (typeid(int) == typeid(n))              ss << (int)             	n;
        if (typeid(long) == typeid(n))             ss << (long)            	n;
        if (typeid(short) == typeid(n))            ss << (short)           	n;
        if (typeid(float) == typeid(n))            ss << (float)           	n;
        if (typeid(double) == typeid(n))           ss << (double)          	n;
        if (typeid(unsigned int) == typeid(n))     ss << (unsigned int)    	n;
        if (typeid(unsigned long) == typeid(n))    ss << (unsigned long)   	n;
        if (typeid(unsigned short) == typeid(n))   ss << (unsigned short)   n;

        if (typeid(n) == typeid(long long int) ||
            typeName == "__int64"              )   ss << (long long int)    n;

        if (typeid(n) == typeid(unsigned long long int) ||
            typeName == "unsigned __int64") ss << (unsigned long long int)  n;

        return ss.str();
    }	
    //---------------------------------------------------------------------------
    /*! ################# Check if a string is number in N Base #################

        Function Name: strIsNum
        Functionality: Check if a string is a valid number.
        Explication:
                        Check if the passed string str is a valid number for
                        the bases: 2,8,10,16.

                        For base 10 accept dots a sign - The sign +
                        not is supported.
                        For base 16 the compare method is case-insensitive.
        Warning:
                        If the pointer param is NULL, then the function
                        throws a char * Exception.

                        If the base is different to the base supported the
                        function do nothing and return 0.
                        
                        On sucess return the length of the string.

        ###################################################################### */

    static unsigned strIsNum(const char *str, short base = 10)
    {
        unsigned i;
        const char *Allowed;
        unsigned dots, sign, spos;
        const char *base2  = "01";
        const char *base8  = "01234567";
        const char *base16 = "0123456789ABCDEFabcdef";

        if (str == NULL)
            throw std::logic_error("The const char * param is a bad pointer.");

        switch (base)
        {
                case 2:  Allowed = base2; break;
                case 8:  Allowed = base8; break;
                case 10:
                        for (i = 0, dots = 0, sign = 0, spos = 0; str[i] != 0; i++)
                        {
                            if (str[i] != '-' && str[i] != '.' &&
                                (str[i] < 48 || str[i] > 57)) return 0;

                            if (str[i] == '-') { sign++; spos = i; }
                            if (str[i] == '.') dots++;
                            if (sign || dots)
                            {
                                if (spos != 0)        return 0;
                                if (sign>1 || dots>1) return 0;
                            }
                        }
                        return i;

                case 16: Allowed = base16; break;
                default: return 0;
        }

        unsigned j,k,z;
        for ( i = 0, j = strlen(str), z = strlen(Allowed); i < j; i++)
        {
                for (k = 0; k < z && Allowed[k] != str[i]; k++);
                if (k == z) return 0;
        }
        return i;
    }	
    //---------------------------------------------------------------------------
    /*! ####################### Convert a number to string ######################

        Function Name: strToNum
        Functionality: Converts a string to number.
        Explication:
                        Converts any  C/C++ string object to number. The
                        object can be STL string or AnsiString from VCL
                        Builder library. Return the converted value as number.

        Warning:
                        If the string isn't a number. throw an Exception.

        ###################################################################### */

    template <typename T> static
    T strToNum(const char *strNum)
    {
        T result = 0;
        string typeName = typeid(result).name();

        if (!strIsNum(strNum))
            throw std::logic_error("The string parameter isn't a number.");

        if (typeid(long) == typeid(result))
            result = atol(strNum);

        if (typeid(unsigned long) == typeid(result))
            result = labs(atol(strNum));

        if (typeid(int) == typeid(result) || typeid(short) == typeid(result))
            result = atoi(strNum);

        if (typeid(float) == typeid(result) || typeid(double) == typeid(result))
            result = atof(strNum);

        if (typeid(unsigned int) == typeid(result) || typeid(unsigned short) == typeid(result))
            result = abs(atoi(strNum));

        if (typeName == "__int64" || typeName == "unsigned __int64" ||
            typeid(long long int) == typeid(result) || typeid(unsigned long long int) == typeid(result))
        {
            unsigned long long int tmpNum = 0;
            short i = (strNum[0] == '-') ? 1 : 0;

            for (; strNum[i] != 0 && strNum[i] != '.' && i < 20; i++)
                    tmpNum = (tmpNum << 3) + (tmpNum << 1) + (strNum[i]-48);

            if ((strNum[0] == '-' && typeName == "__int64") ||
                typeName == "long long int")
                result = tmpNum * -1;
            else
                return tmpNum;
        }

        return result;
    }
    //---------------------------------------------------------------------------
    /*! ############# Splits the path and file name with extension ##############

        Function Name: splitPathNameExt
        Functionality: Splits the path and the name with the extension from complete path.
        Explication:
                        Extracts the filename with extension from string with a complete
                        path.

        ###################################################################### */

    static void splitPathNameExt(const char *cPath, string &path, string &fileName, string &ext)
    {
        int pos;

        ext  = "";
        path = "";
        fileName = cPath;

        if ((pos = AnsiStr::charRFind(cPath,OP_SLASH)) != -1)
        {
            path = cPath;
            fileName = cPath;

            fileName.erase(0,pos+1);
            path.erase(pos,-1);
        }
        
        if ((pos = AnsiStr::charRFind(fileName.c_str(),'.')) != -1)
        {
            ext  = fileName;

            ext.erase(0,pos+1);
            fileName.erase(pos,-1);
        }
    }
    //---------------------------------------------------------------------------
    /*! ######################## Split a string in tokens #######################

        Function Name: strTokenizaToNum
        Functionality: Split in Tokens a string and save in a vector STL.
        Explication:
                        Split in tokens a string; The separators are given
                        by the const char *sep. The tokens are saved in a
                        vector with a template T that have to be a number
                        Object. i.e. T can be int short float double unsigned
                        __int64 etc.
                        The function return the total tokens in the vector.
        Warning:
                        If someone param is a invalid pointer (NULL) then
                        throws and exception.

        ###################################################################### */

    template <typename T> static
    unsigned strTokenizaToNum(const char *str, const char *sep,
                                vector <T> *tokens,  bool addNullsAsZero = false)
    {
        T result;
        unsigned i,j,k;
        string tmp, strNum;

        if (str == NULL || sep == NULL || tokens == NULL)
            throw std::logic_error("Bad arguments passed.");
        
        for (i = 0; i <= strlen(str); i++)
        {
                for (j = 0, k = 0; sep[j] != 0; j++)
                {
                    if ((AnsiStr::charTolower(str[i]) == AnsiStr::charTolower(sep[j])) || str[i] == 0)
                    {
                        AnsiStr::eraseChars(&tmp," ");
                        if (tmp == "" || AnsiStr::strIsNum(tmp.c_str()))
                        {
                            strNum = (tmp != "") ? tmp : string("0");
                            
                            if (typeid(long) == typeid(result))
                                result = atol(strNum.c_str());
                            
                            if (typeid(unsigned long) == typeid(result))
                                result = labs(atol(strNum.c_str()));
                            
                            if (typeid(int) == typeid(result) || typeid(short) == typeid(result))
                                result = atoi(strNum.c_str());
                            
                            if (typeid(float) == typeid(result) || typeid(double) == typeid(result))
                                result = atof(strNum.c_str());
                            
                            if (typeid(unsigned int) == typeid(result) || typeid(unsigned short) == typeid(result))
                                result = abs(atoi(strNum.c_str()));
                            
                            if (typeid(long long int) == typeid(result) || typeid(unsigned long long int) == typeid(result))
                            {
                                unsigned long long int tmpNum = 0;
                                short i = (strNum[0] == '-') ? 1 : 0;
                                
                                for (; strNum[i] != 0 && strNum[i] != '.' && i < 20; i++)
                                    tmpNum = (tmpNum << 3) + (tmpNum << 1) + (strNum[i]-48);

                                if (strNum[0] == '-' && typeid(long long int) == typeid(result))
                                    result = tmpNum * -1;
                                else
                                    result = tmpNum;
                            }
                            
                            if (tmp != "")
                                tokens->push_back(result);
                            else if (addNullsAsZero)
                                tokens->push_back(result);
                        }
                        
                        k = 1;
                        break;
                    }
                }
                (!k) ? (tmp += str[i]) : (tmp = "");
        }
        return tokens->size();
    }
    //---------------------------------------------------------------------------
    /*! ######################## Split a string in tokens #######################

        Function Name: strTokeniza
        Functionality: Split in Tokens a string and save in a vector STL.
        Explication:
                        Split in tokens a string; The separators are given
                        by the const char *sep. The tokens are saved in a
                        vector with a template T that have to be a String
                        Object. i.e. T can be string STL or AnsiString from
                        VCL Builder Library.
                        The function return the total tokens in the vector.
        Warning:
                        If the T template is invalid (No string Object)
                        then throws a char * Exception. i.e. The char * for
                        the vector is a invalid T.

                        If someone param is a invalid pointer (NULL) then
                        throws and exception.

        ###################################################################### */

    template <typename T> static
    unsigned strTokeniza(const char *str, const char *sep, vector <T> *tokens,
                         bool addNulls = false, bool trim = false, bool erase = false)
    {
        T tmp;
        unsigned i,j,k,s;

        if (str == NULL || sep == NULL || tokens == NULL)
            throw std::logic_error("Bad arguments passed.");

        if (AnsiStr::checkString(tmp) == -1)
            throw std::logic_error("Only Strings 'Objects' are supported.");
        
        s = strlen(str);
        if (erase)
            tokens->clear();

        for (i = 0; i <= s; i++)
        {
             for (j = 0, k = 0; sep[j] != 0; j++)
             {
                  if ((AnsiStr::charTolower(str[i]) == AnsiStr::charTolower(sep[j])) || str[i] == 0)
                  {
                      if (tmp != "")
                      {
                          if (trim)
                              tokens->push_back(*AnsiStr::strTrim(&tmp));
                          else
                              tokens->push_back(tmp);
                      }
                      else if (addNulls)
                          tokens->push_back("");

                      k = 1;
                      break;
                  }
             }
             (!k) ? (tmp += str[i]) : (tmp = "");
        }
        return tokens->size();
    }
    //---------------------------------------------------------------------------
    /*! ######################## Split a string in tokens #######################

        Function Name: strTokeniza
        Functionality: Split in Tokens a string and save in a set STL.
        Explication:
                        Split in tokens a string; The separators are given
                        by the const char *sep. The tokens are saved in a
                        set with a template T that have to be a String
                        Object. i.e. T can be string STL or AnsiString from
                        VCL Builder Library.
                        The function return the total tokens in the set.
        Warning:
                        If the T template is invalid (No string Object)
                        then throws a char * Exception. i.e. The char * for
                        the set is a invalid T.

                        If someone param is a invalid pointer (NULL) then
                        throws and exception.

        ###################################################################### */

    template <typename T> static
    unsigned strTokeniza(const char *str, const char *sep, set <T> *tokens,
                         bool addNulls = false, bool trim = false, bool erase = false)
    {
        T tmp;
        unsigned i,j,k,s;

        if (str == NULL || sep == NULL || tokens == NULL)
            throw std::logic_error("Bad arguments passed.");

        if (AnsiStr::checkString(tmp) == -1)
            throw std::logic_error("Only Strings 'Objects' are supported.");

        s = strlen(str);
        if (erase)
            tokens->clear();

        for (i = 0; i <= s; i++)
        {
             for (j = 0, k = 0; sep[j] != 0; j++)
             {
                  if ((AnsiStr::charTolower(str[i]) == AnsiStr::charTolower(sep[j])) || str[i] == 0)
                  {
                      if (tmp != "")
                      {
                        if (trim)
                            tokens->insert(*AnsiStr::strTrim(&tmp));
                        else
                            tokens->insert(tmp);
                      }
                      else if (addNulls)
                          tokens->insert("");

                      k = 1;
                      break;
                  }
             }
             (!k) ? (tmp += str[i]) : (tmp = "");
        }
        return tokens->size();
    }
    //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    //---------------------------------------------------------------------------
    /*! ######################## Validate a String Date #########################

        Function Name: validateDate
        Functionality: Validates a date string as a valid date.
        Explication:
                        Validate if a string date have the correct strcture
                        for a valid date. The date have days, months, years
                        hours, minutes and seconds. Then check for this values.

                        The format for the argument dateString are:

                                d/m/y h:n:s or d-m-y h:n:s or
                                d/m/y or d-m-y.
                                y/m/d h:n:s or y-m-d h:n:s or
                                y/m/d or y-m-d.

                        Is the string is a valid date return true esle false.

        Warning:
                        When the format is:

                                y/m/d h:n:s or y-m-d h:n:s or
                                y/m/d or y-m-d.

                        Then the validation is only valid if the year is > to
                        the year 31. If the year is less than 31 the validation
                        take the format:

                                d/m/y h:n:s or d-m-y h:n:s or
                                d/m/y or d-m-y.

        ###################################################################### */

    static short validateDate(const char *dateString, vector <long> *dateValues = NULL)
    {
        int pos;
        short dateType = 0;
        unsigned i,s,day,year;
        vector <long> lValues;
        vector <string> Tokens;
        const long months[] = {31,28,31,30,31,30,31,31,30,31,30,31,29};

        s = AnsiStr::strTokeniza(dateString,"-/: ",&Tokens);      // Split in tokens the string date.
        if (s != 3 && s!= 6) return 0;                   // A valid date have 3 or 6 tokens.

        for (i = 0; i < s; i++)
        {
                if (!AnsiStr::strIsNum(Tokens[i].c_str()))           // Validate for only numbers given.
                    return 0;

                lValues.push_back(atol(Tokens[i].c_str())); // Convert the string to number and
        }                                                // save it for next validate the data.

        // Check date format. i.e. if date is in format d-m-y or y-m-d.
        // A month have as a max 31 days. Then if > 31 is a year-month-day format.
        if (lValues[0] > 31) {
            day = 2;
            year = 0;
            dateType = 1;     // Is a year-month-day format
        }
        else {
            day = 0;
            year = 2;
            dateType = 2;     // Is a day-month-year format
        }

        // Validate the month value.
        if (lValues[1] < 1 || lValues[1] > 12)
            return 0;

        // Check if the year is leap year or not.
        if (lValues[1] == 2) pos = (lValues[year]%4 == 0) ? 12 : 1;
        else pos = lValues[1]-1;

        // Validate the day Value.
        if (lValues[day] < 1 || lValues[day] > months[pos])
            return 0;

        // Validate Hours; Minutes; Seconds.
        if(s == 6)
        {
            if (lValues[3] > 24) return 0;
            if (lValues[4] > 59) return 0;
            if (lValues[5] > 59) return 0;
        }

        if (dateValues != NULL) *dateValues = lValues;
        return dateType;
    }
    //---------------------------------------------------------------------------
    /*! ############ Fill the time tm structure from datetime string ############

        Function Name: strToTMStruct
        Functionality: Fill the time tm structure from datetime string.
        Explication:

                    Converts a string date to tm structure.

                    The dateFormat argument indicate the format to use for
                    create the string date. 1 char for Day, Month, Year, Hour,
                    Minute and second.

                    If the params strTime is NULL throws and Exception; If dateFormat
                    param is "" then the default date format is:
                            Format: d/m/y h:n:s

            Warning:

                    If you change the order for the day, month year the result
                    date will be in a bad format.

                    Valid Examples:

                            Format A: d-m-y h:n:s
                            Format B: y/m/d h:n:s

        ###################################################################### */

    static void strToTMStruct(struct tm *tmDate, const char *strTime, const char *dFormat = "")
    {
        string format;              // The datetime format values.
        vector <string> fmtTokens;  // For save the format tokens.
        vector <string> datTokens;  // For save the datetime tokens.

        if (strTime == NULL || dFormat == NULL || tmDate == NULL)
            throw std::logic_error("Bad arguments passed. NULL pointers given");

        format = dFormat;
        AnsiStr::strTolower(&format);
        memset(tmDate,0,sizeof(struct tm)); // Initialize the time struct.

        if (format.empty())                 // If not format then
            format = "d/m/y h:n:s";         // Set default format for datetime.

        unsigned tSize;                     // The arguments tokens size.

        // Get the date arguments in tokens and validate them.
        if ((tSize = AnsiStr::strTokeniza(strTime,"-/: ",&datTokens)) !=
            AnsiStr::strTokeniza(format.c_str(),"-/: ",&fmtTokens) || tSize < 3)
            throw std::logic_error("Bad arguments passed.");

        tmDate->tm_isdst = -1;
        // Set the date values into the tm struct.
        for (unsigned s = 0; s < fmtTokens.size(); s++)
        {
                if (fmtTokens[s] == "d")     // Set Day.
                {
                    tmDate->tm_mday = AnsiStr::strToNum<long>(datTokens[s].c_str());
                    continue;
                }

                if (fmtTokens[s] == "m")     // Set Month.
                {
                    tmDate->tm_mon  = AnsiStr::strToNum<long>(datTokens[s].c_str()) - 1;
                    continue;
                }

                if (fmtTokens[s] == "y")     // Set Year.
                {
                    tmDate->tm_year = AnsiStr::strToNum<long>(datTokens[s].c_str()) - 1900;
                    tmDate->tm_yday = tmDate->tm_year;
                    continue;
                }

                if (fmtTokens[s] == "h")     // Set Hours.
                {
                    tmDate->tm_hour = AnsiStr::strToNum<long>(datTokens[s].c_str());
                    continue;
                }

                if (fmtTokens[s] == "n")     // Set Minutes.
                {
                    tmDate->tm_min  = AnsiStr::strToNum<long>(datTokens[s].c_str());
                    continue;
                }

                if (fmtTokens[s] == "s")     // Set Seconds.
                {
                    tmDate->tm_sec  = AnsiStr::strToNum<long>(datTokens[s].c_str());
                    continue;
                }
        }
    }
    //---------------------------------------------------------------------------
    /*! #################### Return a date string as number #####################

        Function Name: strToTime
        Functionality: Converts string date to long date number.
        Explication:

                    Converts a string date to long date number. The long number is
                    the UNIX time format. Seconds elapsed since JAN/01/1970.

                    The dateFormat argument indicate the format to use for
                    create the string date. 1 char for Day, Month, Year, Hour,
                    Minute and second.

                    If the params strTime is NULL throws and Exception; If dateFormat
                    param is "" then the default date format is:
                            Format: d/m/y h:n:s

            Warning:

                    If you change the order for the day, month year the result
                    date will be in a bad format.

                    Valid Examples:

                            Format A: d-m-y h:n:s
                            Format B: y/m/d h:n:s

        ###################################################################### */

    static long strToTime(const char *strTime, const char *dateFormat = "")
    {
        struct tm tmDate;

        AnsiStr::strToTMStruct(&tmDate,strTime,dateFormat);

        return mktime(&tmDate);
    }
    //---------------------------------------------------------------------------
    /*! ############ Get the Date as String From Excel number format ############

        Function Name: serialToStringDate
        Functionality: Return a string as Excel date format from long number date.
        Explication:
                       Converts a long Excel date number to a datestring.

                       The format return values as a dateString are:

                              When the format is 0: d/m/y
                              When the format is 1: d-m-y
                              When the format is 2: y/m/d
                              When the format is 3: y-m-d
        Warning:
                       If format is invalid integer return the date as format 0.
                       If the return type var isn't a valid string object, then
                       throws an Exception. Valid objects: AnsiString for
                       VCL Builder C++ or string for STL C++.

        ###################################################################### */

    template <typename T> static
    T serialToStringDate(unsigned long nSerialDate, unsigned short format = 0)
    {
        char buff[64];
        long l, n, i, j;
        T Date = "29/02/1900";
        long nDay, nMonth, nYear;

        if (checkString(Date) == -1)
            throw "The return data must be a String object.";

        if (nSerialDate == 60) return Date;
        else if (nSerialDate < 60) nSerialDate++;

        // Modified Julian to DMY calculation with an addition of 2415019
        l = nSerialDate + 68569 + 2415019;
        n = long(( 4 * l ) / 146097);
        l = l - long(( 146097 * n + 3 ) / 4);
        i = long(( 4000 * ( l + 1 ) ) / 1461001);
        l = l - long(( 1461 * i ) / 4) + 31;
        j = long(( 80 * l ) / 2447);
        nDay = l - long(( 2447 * j ) / 80);
        l = long(j / 11);
        nMonth = j + 2 - ( 12 * l );
        nYear = 100 * ( n - 49 ) + i + l;

        switch (format)
        {
            case 0:  sprintf(buff,"%.2ld/%.2ld/%ld",nDay,nMonth,nYear); break;
            case 1:  sprintf(buff,"%.2ld-%.2ld-%ld",nDay,nMonth,nYear); break;
            case 2:  sprintf(buff,"%ld/%.2ld/%.2ld",nYear,nMonth,nDay); break;
            case 3:  sprintf(buff,"%ld-%.2ld-%.2ld",nYear,nMonth,nDay); break;
            default: sprintf(buff,"%.2ld/%.2ld/%ld",nDay,nMonth,nYear); break;
        }

        Date = buff;

        return Date;
    }
    //---------------------------------------------------------------------------
    /*! ############## Return a DateString as Excel number Format ###############

        Function Name: stringDateToSerial
        Functionality: Converts string date to Excel number format.
        Explication:
                       The string date argument passed is converted as a long
                       number that represents the Excel number format for that
                       date.

                       The format for the argument dateString are:

                              d/m/y or d-m-y.
                              y/m/d or y-m-d.

                       Is the string is a valid date return the Excel date as number.

        Warning:
                       When the format is:

                              y/m/d h:n:s or y-m-d h:n:s or
                              y/m/d or y-m-d.

                       Then the validation is only valid if the year is > to
                       the year 31. If the year is less than 31 the validation
                       take the format:

                              d/m/y h:n:s or d-m-y h:n:s or
                              d/m/y or d-m-y.

        ###################################################################### */

    static long stringDateToSerial(const char *dateString)
    {
        vector <long> tokens;
        long nDay, nMonth, nYear;

        if (!validateDate(dateString,&tokens))
            throw "The String date have a bad format.";

        // Check date format. i.e. if date is in format d-m-y or y-m-d.
        // A month have as a max 31 days. Then if > 31 is a year-mont-day format.
        if (tokens[0] > 31) {
            nDay   = tokens[2];
            nYear  = tokens[0];
        }
        else {
            nDay   = tokens[0];
            nYear  = tokens[2];
        }

        nMonth = tokens[1];

        // Excel/Lotus 123 have a bug with 29-02-1900. 1900 isn't a
        // leap year, but Excel/Lotus 123 think it is...
        if (nDay  == 29 && nMonth == 02 &&
            nYear == 1900) return 60;

        // DMY to Modified Julian calculatie with an extra substraction of 2415019.
        long nSerialDate =
                          long((1461 * (nYear + 4800 + long((nMonth-14)/12)))/4) +
                          long((367  * (nMonth - 2 - 12 * ((nMonth-14)/12)))/12) -
                          long((3    * (long((nYear + 4900 + long((nMonth-14)/12))/100)))/4) +
                          nDay - 2415019 - 32075;

        // Because of the 29-02-1900 bug, any serial date
        // under 60 is one off... Compensate.
        if (nSerialDate < 60)
            nSerialDate--;

        return nSerialDate;
    }
    //---------------------------------------------------------------------------
    /*! #################### Return a date number as string #####################

        Function Name: timeToStr
        Functionality: Converts long date number to string date.
        Explication:

                    Converts a long date number to string. The long number is
                    the UNIX time format. Seconds elapsed since JAN/01/1970.

                    The dateFormat argument indicate the format to use for
                    create the string date. 1 char for Day, Month, Year, Hour,
                    Minute second and optional for t:

                           Where t indicate 12 hours format use and this
                           value is automatic assigned for p.m. or a.m.

                    If you want the day name and month name in the string date
                    result, then the format have to be the next:

                           Format 1: ddddd-mmm-y h:n:s
                           Format 2: ddddd/mmm/y h:n:s t

                    If the params are NULL and 0 then the date returned is
                    the current date with the format:
                           Format: d/m/y h:n:s

         Warning:

                    If you change the order for the day, month year the result
                    date will be in a bad format and throws an Exception.

                    Valid Examples:

                           Format A: d-m-y h:n:s t
                           Format B: y/m/d h:n:s t

        ###################################################################### */

    template <typename T> static
    T timeToStr(const char *dateFormat=NULL, long timer = 0)
    {
        T Date;
        char sep;
        char dig[6];
        time_t ltimer;
        string format;
        struct tm *mdate;
        vector <T> Tokens;
        const char *wDays[7]   = {"Sun","Mon","Tue","Wed",
                                  "Thu","Fri","Sat"};
        const char *months[12] = {"Jan","Feb","Mar","Apr","May","Jun",
                                  "Jul","Agu","Sep","Oct","Nov","Dec"};

        format = (dateFormat == NULL) ? "d/m/y h:n:s" : dateFormat;
        strTolower(&format);
        sep = (format.find('-') != string::npos) ? '-' : '/';
        ltimer = (timer == 0) ? time(NULL) : timer;
        mdate = localtime(&ltimer);

        if (strTokeniza(format.c_str(),"-/: ",&Tokens) < 6)
            throw "Bad format arguments passed.";

        for (unsigned s = 0; s < Tokens.size(); s++)
        {
            if (Tokens[s] == "ddddd")
            {
                if (s != 0)
                    throw "Bad format argument passed. For date.";

                Date  = wDays[mdate->tm_wday];  // Set the Name of the Week.
                Date += ", ";
                sprintf(dig,"%.1d ",mdate->tm_mday);
                Date += dig;        			// Day as number.
                continue;
            }

            if (Tokens[s] == "d") {
                sprintf(dig,"%.2d",mdate->tm_mday);
                Date += dig;         			// Set Day.
                continue;
            }

            if (Tokens[s] == "mmm")
            {
                if (s != 1)
                    throw "Bad format argument passed. For Month.";

                Date += months[mdate->tm_mon];  // Month Name
                Date += " ";
                continue;
            }

            if (Tokens[s] == "m") {
                sprintf(dig,"%c%.2d%c",sep,mdate->tm_mon+1,sep);
                Date += dig;        			// Set Month.
                continue;
            }

            if (Tokens[s] == "y") {
                sprintf(dig,"%d",mdate->tm_year+1900);
                Date += dig;        			// Set Year.
                continue;
            }

            if (Tokens[s] == "h")   			// Set Hours.
            {
                if (Tokens[Tokens.size()-1] == "t")
                    sprintf(dig,"%.2d:",(mdate->tm_hour > 12) ?
                           (mdate->tm_hour - 12) : (mdate->tm_hour));
                else
                    sprintf(dig,"%.2d:",mdate->tm_hour);

                Date += " ";
                Date += dig;
                continue;
            }

            if (Tokens[s] == "n") {
                sprintf(dig,"%.2d:",mdate->tm_min);
                Date += dig;        			// Set Minutes.
                continue;
            }

            if (Tokens[s] == "s") {
                sprintf(dig,"%.2d",mdate->tm_sec);
                Date += dig;        			// Set Seconds.
                continue;
            }

            if (Tokens[s] == "t")   			// Set timeday.
            {
                if (mdate->tm_hour < 12 || mdate->tm_hour == 24) Date += " a.m.";
                if (mdate->tm_hour > 11 && mdate->tm_hour <= 23) Date += " p.m.";
            }
        }
        return Date;
    }
    //---------------------------------------------------------------------------
    /*! ################ Return the days elapsed between 2 dates ################

        Function Name: daysElapsed
        Functionality: Return the numbers of days elapsed between to dates.
        Explication:

                       Return the numbers of days elapsed between to dates.
                       A valid dates format examnple:

                             Format A: d-m-y or d/m/y
                             Format B: y/m/d or y-m-d

         Warning:

                       If the dates params have a bad format the the function
                       throws an Exception.

        ###################################################################### */

    static long daysElapsed(const char *fDate, const char *sDate)
    {
        long fd,sd;

        fd = stringDateToSerial(fDate);
        sd = stringDateToSerial(sDate);

        return labs(fd-sd);
    }
};
//---------------------------------------------------------------------------
#endif
