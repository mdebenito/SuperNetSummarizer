package supernetsummarizer;

import org.apache.commons.net.util.SubnetUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Main library class.
 */
public class SuperNetSummarizer {
    /**
     * Logger Object (Log4j2)
     */
    public static Logger logger = LogManager.getLogger(SuperNetSummarizer.class);

    /**
     * Summarizes the list of strings into Supernets.
     * @param addresses List of strings corresponding to IP addresses or CIDR ranges.
     * @return List of strings containing the biggest possible supernets and the leftover IP addresses after summarizing the input list
     * @throws UnknownHostException
     */
    public static List<String> summarize(List<String> addresses) throws UnknownHostException {
        return briefIpList(addresses);
    }

    /**
     * Checks if a string is a valid IP address
     * @param line String to check
     * @return true if the string is a valid IP address
     */
    public static boolean isValidIp(String line) {
        final String IPADDRESS_PATTERN =
                "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";
        Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
        return pattern.matcher(line).matches();
    }

    /**
     * Checks if a string is a valid CIDR range
     * @param line String to check
     * @return true if the string is a valid CIDR range
     */
    public static boolean isValidCIDRRange(String line){

        final String CIDR_PATTERN =
                "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])(/([0-9]|[1-2][0-9]|3[0-2]))$";
        Pattern pattern = Pattern.compile(CIDR_PATTERN);
        return pattern.matcher(line).matches();
    }

    /**
     * Method that actually performs the summarization
     * @param ipAddresses List of strings to summarize
     * @return Summarized list of strings
     * @throws UnknownHostException
     */
    private static List<String> briefIpList(List<String> ipAddresses) throws UnknownHostException {
        List<String> result = new ArrayList<>();
        List<String> ranges = new ArrayList<>();
        List<String> ips = new ArrayList<>();

        //Extract ranges and add them to their own list.
        //Extract IPs and add them to their own list
        for(String ip : ipAddresses){
            if(isValidCIDRRange(ip)){
                ranges.add(ip);
            }else if(isValidIp(ip)){
                ips.add(ip);
            }
        }
        for(int mask = 16; mask<=30 ; mask++) {
            for(int i=0;i<ips.size();i++){
                InetAddress tempAddr = InetAddress.getByName(ips.get(i));
                boolean found = false;
                for(String range :ranges){
                    SubnetUtils tempCidr = new SubnetUtils(range);
                    if(tempCidr.getInfo().isInRange(tempAddr.toString().replace("/","")) ||
                            tempCidr.getInfo().getNetworkAddress().equals(tempAddr.toString().replace("/","")) ||
                            tempCidr.getInfo().getBroadcastAddress().equals(tempAddr.toString().replace("/",""))){
                        found = true;
                    }
                }
                if(!found){
                    SubnetUtils ourCIDRRange = new SubnetUtils(ips.get(i)+"/"+mask);
                    List<String> addressesInThisRange = new ArrayList<>();
                    for(int k=i;k<ips.size() ;k++){
                        if(ourCIDRRange.getInfo().isInRange(ips.get(k))){
                            addressesInThisRange.add(ips.get(k));
                        }
                    }
                    if(addressesInThisRange.size()>0){
                        double minimumNumberOfIpAddresses = Math.pow(2,32-mask)-2;
                        if(addressesInThisRange.size()==minimumNumberOfIpAddresses){ //Got a full range
                            ranges.add(ourCIDRRange.getInfo().getNetworkAddress()+"/"+mask);
                        }
                    }
                }
            }
        }

        //Discard ips included in the known ranges
        for(String ip : ips){
            boolean contained = false;
            for(String range : ranges){
                SubnetUtils snu = new SubnetUtils(range);
                SubnetUtils.SubnetInfo info = snu.getInfo();
                boolean inRange = info.isInRange(ip);
                if(inRange)
                    contained = true;
            }
            if(!contained)
                result.add(ip);
        }

        result.addAll(ranges);

        return result;
    }
}
