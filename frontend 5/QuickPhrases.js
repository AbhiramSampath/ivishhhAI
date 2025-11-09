import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import { Svg, Path, Circle } from 'react-native-svg';
import { getPhrasebook } from './api';

// Speaker icon components
const InactiveSpeakerIcon = () => (
  <View style={styles.phaseSpeaker}>
    <Svg width={21} height={18} viewBox="0 0 21 18" fill="none">
      <Path
        d="M13 5.00024C13.621 5.46598 14.125 6.0699 14.4721 6.76418C14.8193 7.45845 15 8.22402 15 9.00024C15 9.77647 14.8193 10.542 14.4721 11.2363C14.125 11.9306 13.621 12.5345 13 13.0002M15.7 2.00024C16.744 2.84389 17.586 3.91037 18.1645 5.12156C18.7429 6.33276 19.0432 7.658 19.0432 9.00024C19.0432 10.3425 18.7429 11.6677 18.1645 12.8789C17.586 14.0901 16.744 15.1566 15.7 16.0002M4 12.0002H2C1.73478 12.0002 1.48043 11.8949 1.29289 11.7073C1.10536 11.5198 1 11.2654 1 11.0002V7.00022C1 6.735 1.10536 6.48065 1.29289 6.29311C1.48043 6.10557 1.73478 6.00022 2 6.00022H4L7.5 1.50022C7.5874 1.33045 7.73265 1.19754 7.90949 1.12551C8.08633 1.05348 8.2831 1.04708 8.46425 1.10746C8.6454 1.16784 8.79898 1.29103 8.89723 1.45476C8.99549 1.61849 9.03194 1.81196 9 2.00022V16.0002C9.03194 16.1885 8.99549 16.3819 8.89723 16.5457C8.79898 16.7094 8.6454 16.8326 8.46425 16.893C8.2831 16.9534 8.08633 16.947 7.90949 16.8749C7.73265 16.8029 7.5874 16.67 7.5 16.5002L4 12.0002Z"
        stroke="#F6F6F8"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </Svg>
  </View>
);

const ActiveSpeakerIcon = () => (
  <View style={styles.phaseSpeakerContainer}>
    <Svg style={styles.ellipse309} width="52" height="52" viewBox="0 0 52 52" fill="none">
      <Circle cx="26" cy="26" r="26" fill="#787878" fillOpacity="0.2"/>
    </Svg>
    <Svg style={styles.ellipse310} width="66" height="66" viewBox="0 0 66 66" fill="none">
      <Circle opacity="0.5" cx="33" cy="33" r="33" fill="#787878" fillOpacity="0.2"/>
    </Svg>
    <View style={styles.iconsDarkInactive}>
      <Svg width="21" height="18" viewBox="0 0 21 18" fill="none">
        <Path 
          d="M13 5.00024C13.621 5.46598 14.125 6.0699 14.4721 6.76418C14.8193 7.45845 15 8.22402 15 9.00024C15 9.77647 14.8193 10.542 14.4721 11.2363C14.125 11.9306 13.621 12.5345 13 13.0002M15.7 2.00024C16.744 2.84389 17.586 3.91037 18.1645 5.12156C18.7429 6.33276 19.0432 7.658 19.0432 9.00024C19.0432 10.3425 18.7429 11.6677 18.1645 12.8789C17.586 14.0901 16.744 15.1566 15.7 16.0002M4 12.0002H2C1.73478 12.0002 1.48043 11.8949 1.29289 11.7073C1.10536 11.5198 1 11.2654 1 11.0002V7.00022C1 6.735 1.10536 6.48065 1.29289 6.29311C1.48043 6.10557 1.73478 6.00022 2 6.00022H4L7.5 1.50022C7.5874 1.33045 7.73265 1.19754 7.90949 1.12551C8.08633 1.05348 8.2831 1.04708 8.46425 1.10746C8.6454 1.16784 8.79898 1.29103 8.89723 1.45476C8.99549 1.61849 9.03194 1.81196 9 2.00022V16.0002C9.03194 16.1885 8.99549 16.3819 8.89723 16.5457C8.79898 16.7094 8.6454 16.8326 8.46425 16.893C8.2831 16.9534 8.08633 16.947 7.90949 16.8749C7.73265 16.8029 7.5874 16.67 7.5 16.5002L4 12.0002Z"
          stroke="#F6F6F8"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </Svg>
    </View>
  </View>
);

const SpeakerIcon = ({ isActive, onPress }) => (
  <TouchableOpacity onPress={onPress}>
    {isActive ? <ActiveSpeakerIcon /> : <InactiveSpeakerIcon />}
  </TouchableOpacity>
);

export default function QuickPhrases() {
  const [starredPhrases, setStarredPhrases] = useState({});
  const [activeSpeaker, setActiveSpeaker] = useState(null);
  const [phrases, setPhrases] = useState([]);

  useEffect(() => {
    const fetchPhrases = async () => {
      try {
        const data = await getPhrasebook();
        setPhrases(data);
      } catch (error) {
        console.error('Failed to fetch phrases:', error);
        // Fallback to hardcoded phrases if API fails
        setPhrases([
          {
            id: 1,
            english: 'hey, how much does it cost',
            hindi: 'dost, isaki kimat kitni hai',
          },
          {
            id: 2,
            english: 'Good morning, how are you?',
            hindi: 'Namaste, aap kaise hain?',
          },
        ]);
      }
    };
    fetchPhrases();
  }, []);

  const toggleStar = (phraseId) => {
    setStarredPhrases(prevStarred => ({
      ...prevStarred,
      [phraseId]: !prevStarred[phraseId],
    }));
  };

  const toggleSpeaker = (phraseId) => {
    setActiveSpeaker(phraseId);
    setTimeout(() => {
      setActiveSpeaker(null);
    }, 1000); // Reset speaker state after 1 second
  };



  return (
    <View style={styles.quickPhrasesContainer}>
      <Text style={styles.quickPhrases}>Quick Phrases</Text>
      <View style={styles.phraseList}>
        {phrases.map((phrase) => (
          <View style={styles.phrase} key={phrase.id}>
            <View style={styles.frame1542}>
              <Text style={styles.dostisakikimatkitnihai}>{phrase.hindi || phrase.text}</Text>
              <Text style={styles.heyhowmuchdoesitcost}>{phrase.english || phrase.translation}</Text>
            </View>
            <View style={styles.frame1544}>
              <View style={styles.frame1543}>
                <TouchableOpacity onPress={() => toggleStar(phrase.id)}>
                  {starredPhrases[phrase.id] ? (
                    <View style={styles.starredIconContainer}>
                      <Svg width={20} height={20} viewBox="0 0 20 20" fill="none">
                        <Path
                          d="M19.947 7.17901C19.8842 6.99388 19.7685 6.83121 19.6142 6.71107C19.46 6.59094 19.2739 6.51861 19.079 6.50301L13.378 6.05001L10.911 0.589014C10.8325 0.413127 10.7047 0.263736 10.5431 0.158872C10.3815 0.0540081 10.193 -0.00184725 10.0004 -0.00195297C9.80771 -0.0020587 9.61916 0.0535897 9.45745 0.158276C9.29574 0.262963 9.16779 0.412213 9.08903 0.588015L6.62203 6.05001L0.921026 6.50301C0.729482 6.51819 0.546364 6.58822 0.393581 6.70475C0.240798 6.82127 0.124819 6.97934 0.0595194 7.16004C-0.00578038 7.34075 -0.0176359 7.53645 0.0253712 7.72372C0.0683784 7.91099 0.164427 8.0819 0.302026 8.21601L4.51503 12.323L3.02503 18.775C2.97978 18.9703 2.99428 19.1747 3.06665 19.3617C3.13901 19.5486 3.26589 19.7095 3.43083 19.8235C3.59577 19.9374 3.79115 19.9991 3.99161 20.0007C4.19208 20.0022 4.38837 19.9434 4.55503 19.832L10 16.202L15.445 19.832C15.6154 19.9451 15.8162 20.0033 16.0207 19.9988C16.2251 19.9944 16.4232 19.9274 16.5884 19.8069C16.7536 19.6865 16.878 19.5183 16.9448 19.3251C17.0116 19.1318 17.0176 18.9228 16.962 18.726L15.133 12.326L19.669 8.24401C19.966 7.97601 20.075 7.55801 19.947 7.17901Z"
                          stroke="#787878"
                          strokeWidth={2}
                        />
                      </Svg>
                    </View>
                  ) : (
                    <View style={styles.starredIconContainer}>
                      <Svg width={20} height={20} viewBox="0 0 20 20" fill="none">
                        <Path
                          d="M19.947 7.17901C19.8842 6.99388 19.7685 6.83121 19.6142 6.71107C19.46 6.59094 19.2739 6.51861 19.079 6.50301L13.378 6.05001L10.911 0.589014C10.8325 0.413127 10.7047 0.263736 10.5431 0.158872C10.3815 0.0540081 10.193 -0.00184725 10.0004 -0.00195297C9.80771 -0.0020587 9.61916 0.0535897 9.45745 0.158276C9.29574 0.262963 9.16779 0.412213 9.08903 0.588015L6.62203 6.05001L0.921026 6.50301C0.729482 6.51819 0.546364 6.58822 0.393581 6.70475C0.240798 6.82127 0.124819 6.97934 0.0595194 7.16004C-0.00578038 7.34075 -0.0176359 7.53645 0.0253712 7.72372C0.0683784 7.91099 0.164427 8.0819 0.302026 8.21601L4.51503 12.323L3.02503 18.775C2.97978 18.9703 2.99428 19.1747 3.06665 19.3617C3.13901 19.5486 3.26589 19.7095 3.43083 19.8235C3.59577 19.9374 3.79115 19.9991 3.99161 20.0007C4.19208 20.0022 4.38837 19.9434 4.55503 19.832L10 16.202L15.445 19.832C15.6154 19.9451 15.8162 20.0033 16.0207 19.9988C16.2251 19.9944 16.4232 19.9274 16.5884 19.8069C16.7536 19.6865 16.878 19.5183 16.9448 19.3251C17.0116 19.1318 17.0176 18.9228 16.962 18.726L15.133 12.326L19.669 8.24401C19.966 7.97601 20.075 7.55801 19.947 7.17901Z"
                          fill="#787878"
                        />
                      </Svg>
                    </View>
                  )}
                </TouchableOpacity>
                <View style={styles.phaseCopy}>
                  <Svg width={20} height={20} viewBox="0 0 20 20" fill="none">
                    <Path
                      d="M18 0H8C6.897 0 6 0.897 6 2V6H2C0.897 6 0 6.897 0 8V18C0 19.103 0.897 20 2 20H12C13.103 20 14 19.103 14 18V14H18C19.103 14 20 13.103 20 12V2C20 0.897 19.103 0 18 0ZM2 18V8H12L12.002 18H2ZM18 12H14V8C14 6.897 13.103 6 12 6H8V2H18V12Z"
                      fill="#787878"
                    />
                  </Svg>
                </View>
              </View>
              <SpeakerIcon 
                isActive={activeSpeaker === phrase.id} 
                onPress={() => toggleSpeaker(phrase.id)} 
              />
            </View>
          </View>
        ))}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  quickPhrasesContainer: {
    backgroundColor: "#FFF",
    borderRadius: 20,
    paddingHorizontal: 20,
    paddingVertical: 24,
    marginTop: 6,
    marginBottom: 6,
    width: "100%",
  },
  quickPhrases: {
    color: "#000",
    fontSize: 32,
    fontWeight: "500",
    marginBottom: 20,
    fontFamily: "Cabinet Grotesk",
  },
  phraseList: {
    flexDirection: "column",
    gap: 16,
  },
  phrase: {
    backgroundColor: "#FFF",
    borderRadius: 16,
    padding: 12,
    marginBottom: 8,
    flexDirection: "column",
    width: "100%",
  },
  frame1542: {
    marginBottom: 8,
  },
  dostisakikimatkitnihai: {
    color: "#0C0D11",
    fontSize: 26,
    fontWeight: "400",
    fontFamily: "Poppins",
  },
  heyhowmuchdoesitcost: {
    color: "#5E5E5E",
    fontSize: 16,
    fontWeight: "400",
    fontFamily: "Poppins",
  },
  frame1544: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between", // Changed for icon alignment
  },
  frame1543: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
  },
  phraseStarContainer: {
    position: "relative",
    flexShrink: 0,
    height: 24,
    width: 24,
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-start",
    rowGap: 0,
  },
  bxsstarsvg: {
    position: "absolute",
    flexShrink: 0,
    top: -8,
    height: 40,
    left: -8,
    width: 40,
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-start",
    rowGap: 0,
  },
  vector: {
    position: "absolute",
    flexShrink: 0,
    top: 10,
    right: 10,
    bottom: 10,
    left: 10,
    overflow: "visible",
  },
  starredIconContainer: {
    height: 24,
    width: 24,
    justifyContent: 'center',
    alignItems: 'center',
  },
  phraseStar: {
    marginRight: 8,
  },
  phaseCopy: {
    marginRight: 8,
  },
  phaseSpeaker: {
    backgroundColor: "#5E5E5E",
    borderRadius: 20,
    width: 40,
    height: 40,
    alignItems: "center",
    justifyContent: "center",
  },
  phaseSpeakerContainer: { // New styles for active speaker icon
    position: "relative",
    height: 40,
    width: 40,
    backgroundColor: "rgba(94, 94, 94, 1)",
    borderRadius: 20,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  ellipse309: {
    position: "absolute",
    top: -6,
    right: -6,
    bottom: -6,
    left: -6,
  },
  ellipse310: {
    position: "absolute",
    top: -13,
    right: -13,
    bottom: -13,
    left: -13,
  },
  iconsDarkInactive: {
    position: "absolute",
    height: 24,
    width: 24,
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-start",
    justifyContent: "center",
  },
  Vector: {
    position: "relative",
    top: 4,
    right: 3,
    bottom: 4,
    left: 3,
  },
});