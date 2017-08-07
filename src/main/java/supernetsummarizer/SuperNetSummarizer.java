package supernetsummarizer;

import listener.SuperNetSummarizerListener;
import org.apache.commons.net.util.SubnetUtils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Main library class.
 */
public class SuperNetSummarizer {

    private List<SuperNetSummarizerListener> listeners = new ArrayList<>();

    /**
     * Adds a listener to the summarizer events
     * @param l Listener to be added
     */
    public void addListener(SuperNetSummarizerListener l){
        this.listeners.add(l);
    }
    /**
     * Default ranges to explore
     */
    public static int MINIMUM_RANGE_MASK = 8;
    public static int MAXIMUM_RANGE_MASK = 30;

    /**
     * Summarizes the list of strings into Supernets.
     *
     * NOTE: Network address (i.e.: 192.168.1.8 in 192.168.1.8/30) and Broadcast address (i.e.: 192.168.1.11 in 192.168.1.8/30) are not
     * considered to be part of a CIDR range.
     *
     * In situations where they are present in the input list as standalone IP addresses, they will also be present in the output list as such
     * if they are not eligible to be inside a bigger supernet.
     *
     * Examples:
     *  - Input: 192.168.1.8, 192.168.1.9, 192.168.1.10, 192.168.1.11
     *  - Output: 192.168.1.8/30, 192.168.1.8, 192.168.1.11
     *
     *  - Input: 192.168.1.9, 192.168.1.10
     *  - Output: 192.168.1.8/30
     *
     * @param addresses List of strings corresponding to IP addresses and/or CIDR ranges.
     * @return List of strings containing the biggest possible supernets and the leftover IP addresses after summarizing the input list
     * @throws UnknownHostException
     */
    public List<String> summarize(List<String> addresses) throws UnknownHostException {
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
    private List<String> briefIpList(List<String> ipAddresses) throws UnknownHostException, IllegalArgumentException {
        List<String> result = new ArrayList<>();
        List<String> ranges = new ArrayList<>();
        List<String> ips = new ArrayList<>();

        //Extract ranges and deploy them into standalone IPs.
        //Extract IPs and add them to a list
        //We remove any duplicate IPs we might find
        for(String entry : ipAddresses){
            if(!entry.equalsIgnoreCase("")) {
                entry = entry.trim();
                if (isValidCIDRRange(entry)) {
                    publishRangeAnalysisStarted(entry);
                    if(entry.endsWith("/32")){
                        String ipBase = entry.split("/")[0];
                        if (isValidIp(ipBase)) {
                            if(!ips.contains(ipBase))
                                ips.add(ipBase);
                        } else {
                            throw new IllegalArgumentException("The entry '" + entry + "' is not a valid IP address or CIDR range.");
                        }
                    }else {
                        SubnetUtils tempCidr = new SubnetUtils(entry);
                        String[] ipsInRange = tempCidr.getInfo().getAllAddresses();
                        for (String ip : ipsInRange) {
                            if (!ips.contains(ip) && !ipAddresses.contains(ip))
                                ips.add(ip);
                        }
                    }
                }else{
                    if (isValidIp(entry)) {
                        if(!ips.contains(entry))
                            ips.add(entry);
                    } else {
                        throw new IllegalArgumentException("The entry '" + entry + "' is not a valid IP address or CIDR range.");
                    }
                }
            }
        }
        publishSummarizeStart(ips.size());
        //We start with the smallest range and try to build full ranges
        for(int mask = MINIMUM_RANGE_MASK; mask<=MAXIMUM_RANGE_MASK ; mask++) {
            publishMaskStarted(mask);
            for(int i=0;i<ips.size();i++){
                String currentIp = ips.get(i);
                // Check if the IP address is already in a known range. If it is, skip it.
                boolean found = isIpAlreadyInRange(ranges, currentIp);

                if(!found){
                    //The IP is not already contemplated in a larger range. We start a potential full range with it
                    SubnetUtils currentCIDRRange = new SubnetUtils(currentIp+"/"+mask);
                    List<String> addressesInThisRange = new ArrayList<>();
                    //Let's list the IPs that would fit in the current range (including the one that generated it)
                    for(int k=i;k<ips.size() ;k++){
                        String checkIp = ips.get(k);
                        if(currentCIDRRange.getInfo().isInRange(checkIp)){
                            addressesInThisRange.add(checkIp);
                        }
                    }
                    //If we have enough addresses to fill a range
                    if(addressesInThisRange.size()>0){
                        double minimumNumberOfIpAddresses = Math.pow(2,32-mask)-2;
                        if(addressesInThisRange.size()==minimumNumberOfIpAddresses){ //Got a full range
                            ranges.add(currentCIDRRange.getInfo().getNetworkAddress()+"/"+mask);
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
        Collections.sort(result);
        return result;
    }

    private void publishMaskStarted(int mask) {
        for(SuperNetSummarizerListener l : listeners){
            l.processingMask(mask);
        }
    }

    private void publishSummarizeStart(int size) {
        for(SuperNetSummarizerListener l : listeners){
            l.summarizingStarted(size);
        }
    }

    private void publishRangeAnalysisStarted(String entry) {
        for(SuperNetSummarizerListener l : listeners){
            l.analysingRange(entry);
        }
    }

    /**
     * Checks if a given IP address is contained in any of the given CIDR ranges. In this particular case, Network and Broadcast
     * addresses are considered part of the range to avoid duplicate ranges. That IP addresses are added in the end as standalone
     * addresses if they do not fit inside larger ranges.
     * @param ranges List of CIDR ranges to check
     * @param ipAddress IP Address to search
     * @return True if the address corresponds to any known range
     */
    private boolean isIpAlreadyInRange(List<String> ranges, String ipAddress) throws UnknownHostException {
        boolean found = false;
        InetAddress tempAddr = InetAddress.getByName(ipAddress);
        for(String range : ranges){
            SubnetUtils tempCidr = new SubnetUtils(range);
            if(tempCidr.getInfo().isInRange(tempAddr.toString().replace("/","")) ||
                    tempCidr.getInfo().getNetworkAddress().equals(tempAddr.toString().replace("/","")) ||
                    tempCidr.getInfo().getBroadcastAddress().equals(tempAddr.toString().replace("/",""))){
                found = true;
            }
        }
        return found;
    }
}
