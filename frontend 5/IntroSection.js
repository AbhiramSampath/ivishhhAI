import React, { useState, useEffect } from 'react';
import { View, Text, StyleSheet, ImageBackground, Dimensions, TouchableOpacity } from 'react-native';
import Svg, { G, Path } from 'react-native-svg';
// Import Icon from react-native-vector-icons (ensure this library is installed)
import Icon from 'react-native-vector-icons/FontAwesome';
import { useNavigation } from '@react-navigation/native';
import { getUserDetails } from './api/index';

const { width } = Dimensions.get('window');

export default function IntroSection() {
  const navigation = useNavigation();
  const [userName, setUserName] = useState('User');

  useEffect(() => {
    fetchUserDetails();
  }, []);

  const fetchUserDetails = async () => {
    try {
      const userId = 'dummy_user_token_1234567890'; // Replace with actual user ID
      const data = await getUserDetails(userId);
      setUserName(data.name || 'User');
    } catch (error) {
      console.error('Error fetching user details:', error);
      // Keep default name
    }
  };

  return (
    <View style={styles.introSectionContainer}>
      <Text style={styles.hiDextercontinueleaningJapanese}>
        Hi Dexter✋🏼{'\n'}continue learning Japanese
      </Text>
      <View style={styles.message_perspective_matte}>
        <Svg style={styles.shadow} viewBox="0 0 33 6" fill="none">
          <G>
            <Path
              d="M32.2973 6.88388C25.2253 6.09055 1.37321 3.59268 0.84734 3.52922L16.0907 1.11523L46.2713 4.1979L32.2973 6.88388Z"
              fill="#C4C4C4"
              fillOpacity={0.3}
            />
          </G>
        </Svg>
        <ImageBackground
          style={[styles.img, { width: undefined, height: undefined }, styles.curveline]}
          imageStyle={{ borderRadius: 17 }}
        />
      </View>
      <View style={styles.frame1528}>
        <View style={styles.frame1484}>
          <View style={styles.bxsgridaltsvg}>
            <Svg style={styles.vector} width={26} height={26} viewBox="0 0 26 26" fill="none">
              <Path
                d="M6.63606 17.9497L10.8787 13.7071C11.0662 13.5196 11.1716 13.2652 11.1716 13C11.1716 12.7348 11.0662 12.4804 10.8787 12.2929L6.63606 8.05025C6.44852 7.86272 6.19417 7.75736 5.92895 7.75736C5.66373 7.75736 5.40938 7.86272 5.22184 8.05025L0.979201 12.2929C0.791665 12.4804 0.686308 12.7348 0.686308 13C0.686308 13.2652 0.791665 13.5196 0.979201 13.7071L5.22184 17.9497C5.40938 18.1373 5.66373 18.2426 5.92895 18.2426C6.19417 18.2426 6.44852 18.1373 6.63606 17.9497ZM13.7071 10.8787L17.9498 6.63604C18.1373 6.4485 18.2427 6.19415 18.2427 5.92893C18.2427 5.66372 18.1373 5.40936 17.9498 5.22183L13.7071 0.979185C13.5196 0.791649 13.2652 0.686291 13 0.686291C12.7348 0.686291 12.4804 0.791648 12.2929 0.979185L8.05027 5.22183C7.86273 5.40936 7.75738 5.66372 7.75738 5.92893C7.75738 6.19415 7.86273 6.4485 8.05027 6.63604L12.2929 10.8787C12.4804 11.0662 12.7348 11.1716 13 11.1716C13.2652 11.1716 13.5196 11.0662 13.7071 10.8787ZM13.7071 25.0208L17.9498 20.7782C18.1373 20.5906 18.2427 20.3363 18.2427 20.0711C18.2427 19.8059 18.1373 19.5515 17.9498 19.364L13.7071 15.1213C13.5196 14.9338 13.2652 14.8284 13 14.8284C12.7348 14.8284 12.4804 14.9338 12.2929 15.1213L8.05027 19.364C7.86273 19.5515 7.75738 19.8059 7.75738 20.0711C7.75738 20.3363 7.86273 20.5906 8.05027 20.7782L12.2929 25.0208C12.4804 25.2084 12.7348 25.3137 13 25.3137C13.2652 25.3137 13.5196 25.2084 13.7071 25.0208ZM20.7782 17.9497L25.0208 13.7071C25.2084 13.5196 25.3137 13.2652 25.3137 13C25.3137 12.7348 25.2084 12.4804 25.0208 12.2929L20.7782 8.05025C20.5907 7.86272 20.3363 7.75736 20.0711 7.75736C19.8059 7.75736 19.5515 7.86272 19.364 8.05025L15.1213 12.2929C14.9338 12.4804 14.8284 12.7348 14.8284 13C14.8284 13.2652 14.9338 13.5196 15.1213 13.7071L19.364 17.9497C19.5515 18.1373 19.8059 18.2426 20.0711 18.2426C20.3363 18.2426 20.5907 18.1373 20.7782 17.9497Z"
                fill="black"
              />
            </Svg>
          </View>
          <Text style={styles.verbX}>VerbX</Text>
        </View>
        {/* Profile icon and navigation */}
        <TouchableOpacity
          style={styles.profileIconContainer}
          onPress={() => navigation.navigate('Profile')}
          activeOpacity={0.7}
        >
          <Icon name="user" size={28} color="#4a90e2" />
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  introSectionContainer: {
    fontFamily: "Cabinet Grotesk",
    position: "relative",
    width: "100%",
    backgroundColor: "#F6F6F8",
    borderRadius: 20,
    height: 270,
    marginBottom: 6,
    overflow: 'hidden',
  },
  curveline: {
    position: "absolute",
    top: 198,
    left: 157,
    width: 307,
    height: 115,
    transform: [{ rotate: "-73.87deg" }],
  },
  hiDextercontinueleaningJapanese: {
    fontFamily: "Cabinet Grotesk",
    position: "absolute",
    top: 114,
    left: 20,
    width: 352,
    color: "#000",
    fontSize: 34,
    fontWeight: "500",
    lineHeight: 39,
    fontFamily: "Cabinet Grotesk",
  },
  message_perspective_matte: {
    fontFamily: "Cabinet Grotesk",
    position: "absolute",
    top: 158,
    left: 20,
    width: 34,
    height: 34,
    alignItems: "center",
    justifyContent: "center",
  },
  shadow: {
    position: "absolute",
    fontFamily: "Cabinet Grotesk",
    top: 29,
    left: 2,
    width: 45,
    height: 6,
    opacity: 0,
  },
  img: {
    bottom: 10,
    fontFamily: "Cabinet Grotesk",
    width: 34,
    height: 34,
    borderRadius: 17,
  },
  frame1528: {
    position: "absolute",
    fontFamily: "Cabinet Grotesk",
    top: 42,
    left: 20,
    width: 'auto', // Adjusted for responsiveness
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    right: 20,
  },
  frame1484: {
    fontFamily: "Cabinet Grotesk",
    flexDirection: "row",
    alignItems: "center",
  },
  bxsgridaltsvg: {
    height: 26,
    fontFamily: "Cabinet Grotesk",
    width: 26,
    marginRight: 6,
  },
  vector: {
    fontFamily: "Cabinet Grotesk",
    width: 26,
    height: 26,
  },
  verbX: {
    fontFamily: "Cabinet Grotesk",
    color: "#000",
    fontSize: 24,
    fontWeight: "500",
    fontFamily: "Cabinet Grotesk",
  },
  profileIconContainer: {
    width: 48,
    height: 48,
    borderRadius: 24,
    backgroundColor: "#F6F6F8",
    alignItems: "center",
    justifyContent: "center",
    zIndex: 10,
    borderWidth: 1,
    borderColor: "#4a90e2",
  },
});