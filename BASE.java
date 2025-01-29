//Find the base address of Position Dependent Code similar to the way Binary Ninja does it with their BASE tool
//@author Me
//@category Embedded
//@keybinding 
//@menupath 
//@toolbar 

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;


public class BASE extends GhidraScript {

	private BigInteger binarySize;
	private BigInteger baseAddress;
	private boolean is32bit;
	
	private SortedSet<BigInteger> getPOI(SymbolTable st) {
		SortedSet<BigInteger> dataPoints = new TreeSet<BigInteger>();
		
		SymbolIterator si = st.getAllSymbols(true);
		
		for( Symbol symbol : si) {
			if(symbol.getName().startsWith("DAT_")) {
    			try {
    				BigInteger value = BigInteger.valueOf(0);
    				if(is32bit) {
    					value = BigInteger.valueOf(getInt(symbol.getAddress())).abs();
    				} else {
    					value = BigInteger.valueOf(getLong(symbol.getAddress())).abs();
    				}
    				
    				dataPoints.add(value);
    			}
    			catch (Exception e) {
    				continue;
    			}
    			
    		}
    	}
		
		return dataPoints;
	}
	
	private Map<BigInteger, HashSet<BigInteger>> getCentroidGroups(SortedSet<BigInteger> dp) {
		Map<BigInteger, HashSet<BigInteger>> groups = new HashMap<BigInteger, HashSet<BigInteger>>();
		
		BigInteger mask;
		
		if(is32bit) {
			mask = BigInteger.valueOf(0xFF000000L);
		} else {
			mask = BigInteger.valueOf(0xFFFF000000000000L);
		}
		
		for(BigInteger bi : dp) {
			groups.put(bi.and(mask), new HashSet<BigInteger>());
		}
		
		return groups;
	}
	
	private double distance(BigInteger p1, BigInteger p2) {
		return Math.sqrt(Math.pow(p1.subtract(p2).doubleValue(), 2.0));
	}
	
	private Map<BigInteger, HashSet<BigInteger>> relocate(Map<BigInteger, HashSet<BigInteger>> centroids) {
		Map<BigInteger, HashSet<BigInteger>> c = new HashMap<BigInteger, HashSet<BigInteger>>();
		
		Set<BigInteger> keys = centroids.keySet();
		
		for(BigInteger bi : keys) {
			BigInteger sum = BigInteger.valueOf(0);
			HashSet<BigInteger> al = centroids.get(bi);
			for(BigInteger val : al) {
				sum = sum.add(val);
			}
			BigInteger newKey = sum.divide(BigInteger.valueOf(al.size()));
			c.put(newKey, al);
		}
		
		return c;
	}
	
	private Map<BigInteger, HashSet<BigInteger>> cluster(Map<BigInteger, HashSet<BigInteger>> centroids, SortedSet<BigInteger> dp) {
		Map<BigInteger, HashSet<BigInteger>> c = new HashMap<BigInteger, HashSet<BigInteger>>();
		
		Set<BigInteger> keys = centroids.keySet();
		
		for(BigInteger d : dp) {
			BigInteger cent = BigInteger.valueOf(0);
			double dist = Double.MAX_VALUE;
			for(BigInteger f : keys) {
				double curDist = this.distance(f,d);
				if(curDist < dist) {
					cent = f;
					dist = curDist;
				}
			}
			
			HashSet<BigInteger> curList = c.get(cent);
			if(curList != null) {
				curList.add(d);
			} else {
				curList = new HashSet<BigInteger>();
				curList.add(d);
				c.put(cent, curList);
			}
		}
		
		return this.relocate(c);
	}
	
	private Map<BigInteger, HashSet<BigInteger>> getLargestXClusters(Map<BigInteger, HashSet<BigInteger>> clusters, int numberToReturn) {
		Map<BigInteger, HashSet<BigInteger>> c = new HashMap<BigInteger, HashSet<BigInteger>>();
		
		if(numberToReturn >= clusters.size()) {
			return clusters;
		}
		
		int i = 0;
		
		while( i < numberToReturn && !monitor.isCancelled()) {
			BigInteger biggest = null;
			int size = 0;
			for (BigInteger bi : clusters.keySet()) {
				if(clusters.get(bi).size() > size) {
					biggest = bi;
					size = clusters.get(bi).size();
				}
			}
			if (biggest != null) {
				c.put(biggest, clusters.get(biggest));
				clusters.remove(biggest);
			}
			i++;
		}
		
		return c;
		
	}
	
	private HashSet<BigInteger> getStrings(int length) {
		DataIterator di = currentProgram.getListing().getDefinedData(true);
		
		HashSet<BigInteger> strings = new HashSet<BigInteger>();
		
		Data data = null;
		String type = null;
		while(di.hasNext() && !monitor.isCancelled()) {
			data = di.next();
			type = data.getDataType().getName().toLowerCase();
			if(type.contains("unicode") || type.contains("string") && data.getDefaultValueRepresentation().length() > length) {
				strings.add(BigInteger.valueOf(Long.parseLong(data.getAddressString(false, true), 16)));
			}
		}
		
		return strings;
		
	}
	
	private Map<BigInteger, BigInteger> findBaseAddressCandidates(Map<BigInteger, HashSet<BigInteger>> clusters, HashSet<BigInteger> strings) {
		Map<BigInteger, BigInteger> candidates = new HashMap<BigInteger, BigInteger>();
		
		BigInteger pageSize = BigInteger.valueOf(1024);
		
		for(BigInteger bi : clusters.keySet()) {
			BigInteger lowerAddress = null;
			BigInteger upperAddress = null;
			if(bi.compareTo(binarySize) > 0) {
				lowerAddress = bi.subtract(binarySize);
				lowerAddress = lowerAddress.subtract(lowerAddress.mod(pageSize));
			} else {
				lowerAddress = BigInteger.valueOf(0);
			}
			upperAddress = bi.add(binarySize);
			upperAddress = upperAddress.subtract(upperAddress.mod(pageSize));
						
			while(lowerAddress.compareTo(upperAddress) <= 0 && !monitor.isCancelled()) {
				long counter = 0;
				
				for(BigInteger str : strings) {
					BigInteger strAddy = lowerAddress.add(str.subtract(baseAddress));
					if(clusters.get(bi).contains(strAddy)) {
						counter++;
					}
				}
				
				if(counter != 0) {
					candidates.put(lowerAddress, BigInteger.valueOf(counter));
				}
				
				lowerAddress = lowerAddress.add(pageSize);
			}
		}
		
		return candidates.entrySet().stream().sorted(Map.Entry.comparingByValue()).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (oldValue, newValue) -> oldValue, LinkedHashMap::new));
	}
	
    public void run() throws Exception {
    	
    	
    	Program program = getCurrentProgram();
    	SymbolTable symbolTable = program.getSymbolTable();
    	
    	Long maxAddress = Long.parseLong(program.getMaxAddress().toString(), 16);
    	Long minAddress = Long.parseLong(program.getMinAddress().toString(), 16);
    	binarySize = BigInteger.valueOf(maxAddress - minAddress);
    	baseAddress = BigInteger.valueOf(Long.parseLong(currentProgram.getImageBase().toString(), 16));
    	
    	if(program.getDefaultPointerSize() == 4) {
    		is32bit = true;
    	} else if (program.getDefaultPointerSize() == 8) {
    		is32bit = false;
    	}
    	
    	long start = System.currentTimeMillis();
    	
    	SortedSet<BigInteger> dataPoints = getPOI(symbolTable);
    	Map<BigInteger, HashSet<BigInteger>> groups = getCentroidGroups(dataPoints);
    	
    	
    	println(String.format("Binary Size: 0x%s", binarySize.toString(16)));
    	println(String.format("Binary Base Address: 0x%s", baseAddress.toString(16)));
    	println(String.format("POI: %d", dataPoints.size()));
    	println(String.format("Smallest POI: 0x%s", dataPoints.first().toString(16)));
    	println(String.format("Largest POI: 0x%s", dataPoints.last().toString(16)));
    	println(String.format("Group size: %d", groups.size()));
    	
    	Map<BigInteger, HashSet<BigInteger>> clust = cluster(groups, dataPoints);
    	
    	while(true && !monitor.isCancelled()) {
    		Map<BigInteger, HashSet<BigInteger>> newClust = cluster(clust, dataPoints);
    		if(newClust.equals(clust)) break;
    		clust = newClust;
    	}
    
    	clust = getLargestXClusters(clust, 5);
    	
    	for(BigInteger key : clust.keySet()) {
    		println(String.format("Cluster %s: %d", key.toString(16), clust.get(key).size()));
    	}
    	
    	HashSet<BigInteger> strings = getStrings(5);
    	println(String.format("Found %d strings", strings.size()));
    	
    	Map<BigInteger, BigInteger> candidates = findBaseAddressCandidates(clust, strings);
    	
    	long stop = System.currentTimeMillis();
    	
    	for(BigInteger cand : candidates.keySet()) {
    		println(String.format("Base Address: %s = %s", cand.toString(16), candidates.get(cand).toString()));
    	}
    	
    	println(String.format("Took %d ms", stop-start));
    }
}
