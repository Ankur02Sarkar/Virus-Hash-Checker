import requests
import argparse
import json

# enter your private key here from virus total
key = 'enter key here'

# validate hash passed by user by checking its length
def checkhash(hsh):
        try:
                if len(hsh) == 32:
                        return hsh
                elif len(hsh) == 40:
                        return hsh
                elif len(hsh) == 64:
                        return hsh
                else:
                        print ("The Hash is Invalid.")
                        exit()
        except Exception:
                        print ('Sorry... Something went wrong with the Hash \n' + Exception)

def main():
        parser = argparse.ArgumentParser(description="MicroSoft CyberSecurity Engage Virus Hash Checker - ANKUR SARKAR")
        parser.add_argument('-o', '--output', required=True, help='Output File Location EX: /Home/Desktop/output.txt ')
        parser.add_argument('-H', '--hash', type=checkhash, required=False, help='Single Hash EX: c41d8ce98f02b214e9823988eca8427e')
        parser.add_argument('-u', '--unlimited', action='store_const', const=1, required=False, help='Changes the 26 second sleep timer to 1.')
        args = parser.parse_args()
                                                                                                                                                                                                                                           
        #Run for hash + key                                                                                                                                                                                                                
        if args.hash and key:                                                                                                                                                                                                              
                file = open(args.output,'w+')                                                                                                                                                                                              
                file.write('\n\nThe following Hash was identified as Malicious.\n\n')                                                                                                                                                              
                file.close()                                                                                                                                                                                                               
                VT_Request(key, args.hash.rstrip(), args.output)                                                                                                                                                                           
                                                                                                                                                                                                                                           
def VT_Request(key, hash, output):
        params = {'apikey': key, 'resource': hash}
        url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        json_response = url.json()
        x = str(json_response)
        x = x.replace("'", '"')
        x = x.replace("False", '"False"')
        x = x.replace("True", '"True"')
        x = x.replace("None", '"None"')

        parsed = json.loads(x)
        y =json.dumps(parsed, indent = 4, sort_keys=True)

        print ("\n")
        response = int(json_response.get('response_code'))
        if response == 0:
                print (y + "\n\n" + hash + ' is not in Virus Total')
                file = open(output,'a')
                file.write(y + "\n\n" + hash + ' is not in Virus Total')
                file.write('\n')
                file.close()
        elif response == 1:
                positives = int(json_response.get('positives'))
                if positives == 0:
                        print (y + "\n\n" + hash + ' is not malicious')
                        file = open(output,'a')
                        file.write(y + "\n\n" + hash + ' is not malicious')
                        file.write('\n')
                        file.close()
                else:
                        print (y + "\n\n" + hash + ' is malicious')
                        file = open(output,'a')
                        file.write(y + "\n\n" + hash + ' is a malicious hash. Hit Count:' + str(positives))
                        file.write('\n')
                        file.close()
        else:
                print (y + "\n\n" + hash + ' could not be searched. Kindly try again later.')

if __name__ == '__main__':
        main()