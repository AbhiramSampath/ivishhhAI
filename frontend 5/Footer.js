import React, { useState, useEffect } from 'react';
import { View, StyleSheet, Dimensions, TouchableOpacity } from 'react-native';
import Svg, { Path, Circle, Defs, RadialGradient, Stop } from 'react-native-svg';
import { useNavigation, useRoute } from '@react-navigation/native';

// Get dynamic window width
const windowWidth = Dimensions.get('window').width;

const FOOTER_HEIGHT = 118;
const MIC_SIZE = 65;
const ORANGE = '#FFA364';
const DEFAULT = '#F6F6F8';
 
// --- Icon Components (No changes, they scale with their parent containers) ---
const HomeIcon = ({ active }) => (
  <Svg width={23} height={22} viewBox="0 0 24 24" fill="none">
    <Path
      d="M0.75 12.9488C0.75 11.6777 0.75 11.0422 0.898331 10.4469C1.02982 9.91915 1.24651 9.41643 1.53988 8.9585C1.87084 8.4419 2.3329 8.00551 3.25701 7.13274L6.50701 4.06329C8.44014 2.23756 9.40671 1.3247 10.5093 0.980305C11.48 0.677138 12.52 0.677138 13.4907 0.980305C14.5933 1.3247 15.5599 2.23756 17.493 4.0633L20.743 7.13274C21.6671 8.00551 22.1292 8.4419 22.4601 8.9585C22.7535 9.41643 22.9702 9.91915 23.1017 10.4469C23.25 11.0422 23.25 11.6777 23.25 12.9488V15.2505C23.25 18.0507 23.25 19.4509 22.705 20.5204C22.2257 21.4612 21.4608 22.2261 20.52 22.7055C19.4504 23.2505 18.0503 23.2505 15.25 23.2505H8.75C5.94974 23.2505 4.54961 23.2505 3.48005 22.7055C2.53924 22.2261 1.77433 21.4612 1.29497 20.5204C0.75 19.4509 0.75 18.0507 0.75 15.2505V12.9488Z"
      stroke={active ? ORANGE : DEFAULT}
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      fill={active ? ORANGE : 'none'}
    />
  </Svg>
);

const ChatIcon = ({ active }) => (
  <Svg width={23} height={23} viewBox="0 0 26 26" fill="none">
    <Path
      fillRule="evenodd"
      clipRule="evenodd"
      d="M21.2498 21.2483C17.6843 24.8142 12.4047 25.5846 8.08407 23.5865C7.44624 23.3297 6.92332 23.1222 6.42619 23.1222C5.04149 23.1304 3.31795 24.473 2.42217 23.5783C1.5264 22.6824 2.87006 20.9575 2.87006 19.5645C2.87006 19.0673 2.67074 18.5537 2.41396 17.9146C0.414888 13.5947 1.18638 8.3133 4.75189 4.74857C9.30345 0.195333 16.6983 0.195333 21.2498 4.7474C25.8096 9.30767 25.8014 16.6963 21.2498 21.2483Z"
      stroke={active ? ORANGE : DEFAULT}
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      fill={active ? ORANGE : 'none'}
    />
    <Path d="M17.5959 13.4818H17.6064" stroke={active ? "#0C0D11" : "white"} strokeWidth={active ? "3" : "2.33"} strokeLinecap="round" strokeLinejoin="round" />
    <Path d="M12.9187 13.4818H12.9292" stroke={active ? "#0C0D11" : "white"} strokeWidth={active ? "3" : "2.33"} strokeLinecap="round" strokeLinejoin="round" />
    <Path d="M8.2415 13.4818H8.252" stroke={active ? "#0C0D11" : "white"} strokeWidth={active ? "3" : "2.33"} strokeLinecap="round" strokeLinejoin="round" />
  </Svg>
);

const CameraIcon = ({ active }) => (
  <Svg width={23} height={23} viewBox="0 0 24 22" fill="none">
    <Path
      fillRule="evenodd"
      clipRule="evenodd"
      d="M15.5471 1.72651C16.7254 2.19551 17.0859 3.82884 17.5677 4.35384C18.0496 4.87884 18.7391 5.05734 19.1206 5.05734C21.1482 5.05734 22.7921 6.70117 22.7921 8.72767V15.4885C22.7921 18.2068 20.5871 20.4118 17.8687 20.4118H6.13207C3.41257 20.4118 1.20874 18.2068 1.20874 15.4885V8.72767C1.20874 6.70117 2.85257 5.05734 4.88024 5.05734C5.26057 5.05734 5.95007 4.87884 6.43307 4.35384C6.91491 3.82884 7.27424 2.19551 8.45257 1.72651C9.63207 1.25751 14.3687 1.25751 15.5471 1.72651Z"
      stroke={active ? ORANGE : DEFAULT}
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      fill={active ? ORANGE : 'none'}
    />
    <Path d="M18.4113 8.08333H18.4218" stroke="white" strokeWidth={2.33} strokeLinecap="round" strokeLinejoin="round" />
    <Path
      fillRule="evenodd"
      clipRule="evenodd"
      d="M15.7089 12.316C15.7089 10.2673 14.0488 8.60718 12.0001 8.60718C9.95143 8.60718 8.29126 10.2673 8.29126 12.316C8.29126 14.3647 9.95143 16.0248 12.0001 16.0248C14.0488 16.0248 15.7089 14.3647 15.7089 12.316Z"
      stroke="white"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      fill="none"
    />
  </Svg>
);

const PhrasebookIcon = ({ active }) => (
  <Svg width={22} height={24} viewBox="0 0 22 24" fill="none">
    <Path
      fillRule="evenodd"
      clipRule="evenodd"
      d="M15.5598 1.20801C15.5598 1.20801 6.60332 1.21267 6.58932 1.21267C3.36932 1.23251 1.37549 3.35117 1.37549 6.58284V17.3115C1.37549 20.5595 3.38449 22.6863 6.63249 22.6863C6.63249 22.6863 15.5878 22.6828 15.603 22.6828C18.823 22.663 20.818 20.5432 20.818 17.3115V6.58284C20.818 3.33484 18.8078 1.20801 15.5598 1.20801Z"
      stroke={active ? ORANGE : DEFAULT}
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      fill={active ? ORANGE : 'none'}
    />
    <Path
      d="M15.3354 16.9273H6.91211"
      stroke={active ? "#0C0D11" : "white"}
      strokeWidth={active ? "2" : "1.75"}
      strokeLinecap="round"
      strokeLinejoin="round"
      fill="none"
    />
    <Path
      d="M15.3354 12.0431H6.91211"
      stroke={active ? "#0C0D11" : "white"}
      strokeWidth={active ? "2" : "1.75"}
      strokeLinecap="round"
      strokeLinejoin="round"
      fill="none"
    />
    <Path
      d="M10.1263 7.17025H6.91211"
      stroke={active ? "#0C0D11" : "white"}
      strokeWidth={active ? "2" : "1.75"}
      strokeLinecap="round"
      strokeLinejoin="round"
      fill="none"
    />
  </Svg>
);

const MicSvgIcon = ({ active }) => (
  <Svg width={28} height={28} viewBox="0 0 29 29" fill="none">
    <Path
      d="M19.6119 14.3386V7.33863C19.6119 4.75213 17.5294 2.64746 14.9697 2.64746C14.8876 2.64795 14.8058 2.65774 14.7259 2.67663C13.528 2.7347 12.3983 3.25104 11.5705 4.1188C10.7427 4.98657 10.2802 6.13935 10.2786 7.33863V14.3386C10.2786 16.9123 12.3716 19.0053 14.9452 19.0053C17.5189 19.0053 19.6119 16.9123 19.6119 14.3386ZM12.6119 14.3386V7.33863C12.6119 6.05179 13.6584 5.00529 14.9452 5.00529C15.009 5.00532 15.0727 4.99946 15.1354 4.98779C16.3312 5.07529 17.2786 6.09613 17.2786 7.33863V14.3386C17.2786 15.6255 16.2321 16.672 14.9452 16.672C13.6584 16.672 12.6119 15.6255 12.6119 14.3386Z"
      fill={active ? ORANGE : 'white'}
    />
    <Path
      d="M7.94539 14.3386H5.61206C5.61206 19.0893 9.18323 23.014 13.7787 23.5915V26.0053H16.1121V23.5915C20.7076 23.014 24.2787 19.0905 24.2787 14.3386H21.9454C21.9454 18.1991 18.8059 21.3386 14.9454 21.3386C11.0849 21.3386 7.94539 18.1991 7.94539 14.3386Z"
      fill={active ? ORANGE : 'white'}
    />
  </Svg>
);

// Footer Background (no ellipse highlight)
const FooterBackground = ({ width }) => (
  <Svg width={width} height={FOOTER_HEIGHT} style={StyleSheet.absoluteFill} preserveAspectRatio='none'>
    <Path
      d="M393 120H0V0C0 11.0457 8.95431 20 20 20H133.372C140.812 20 144.533 20 146.918 21.4416C149.303 22.8831 151.975 27.972 157.32 38.1496C164.717 52.2348 179.486 61.8418 196.5 61.8418C213.514 61.8417 228.283 52.2348 235.68 38.1496C241.025 27.972 243.697 22.8831 246.082 21.4416C248.467 20 252.188 20 259.628 20H373C384.046 20 393 11.0457 393 0V120Z"
      fill="#05070B"
      scaleX={width / 393} // Scales horizontally to fit screen width
      scaleY={1} // Keeps vertical scale
    />
  </Svg>
);

// Mic Glow
const MicGlow = () => (
  <Svg width={MIC_SIZE} height={MIC_SIZE} style={StyleSheet.absoluteFill}>
    <Defs>
      <RadialGradient id="glow" cx="50%" cy="50%" r="50%" fx="50%" fy="50%">
        <Stop offset="0%" stopColor={ORANGE} stopOpacity="0.2" />
        <Stop offset="100%" stopColor={ORANGE} stopOpacity="0" />
      </RadialGradient>
    </Defs>
    <Circle cx={MIC_SIZE / 2} cy={MIC_SIZE / 2} r={MIC_SIZE / 2} fill="url(#glow)" />
  </Svg>
);

const Footer = () => {
  const navigation = useNavigation();
  const route = useRoute();
  const [screenWidth, setScreenWidth] = useState(windowWidth);

  useEffect(() => {
    const updateWidth = () => {
      setScreenWidth(Dimensions.get('window').width);
    };

    const subscription = Dimensions.addEventListener('change', updateWidth);
    return () => subscription?.remove();
  }, []);

  // Get the current route name and map it to our footer screen names
  const getActiveScreen = () => {
    const routeName = route.name;
    switch (routeName) {
      case 'Home':
        return 'home';
      case 'ChatList':
        return 'chat';
      case 'Camera':
        return 'camera';
      case 'Phrasebook':
        return 'phrasebook';
      case 'Microphone':
        return 'mic';
      default:
        return 'home';
    }
  };

  const active = getActiveScreen();
 
  const handlePress = (screen) => {
    if (screen === 'phrasebook') {
      navigation.navigate('Phrasebook');
    }
  
    else if (screen === 'home') {
      navigation.navigate('Home');
    }
    else if (screen === 'chat') {
      navigation.navigate('ChatList');
    }
    else if (screen === 'camera') {
      navigation.navigate('ARTranslate1');
    }
    else if (screen === 'mic') {
      navigation.navigate('Translate2');
    }
  };

  return (
    <View style={[styles.container, { width: '100%' }]}>
      <FooterBackground width={screenWidth} />

      <View style={[styles.leftNav, { 
        left: Math.max(20, screenWidth * 0.075), // At least 20px, or 7.5% of screen width
        width: Math.min(120, screenWidth * 0.3) // At most 120px, or 30% of screen width
      }]}>
        <TouchableOpacity style={styles.iconBtn} onPress={() => handlePress('home')}>
          <HomeIcon active={active === 'home'} />
        </TouchableOpacity>
        <TouchableOpacity style={styles.iconBtn} onPress={() => handlePress('chat')}>
          <ChatIcon active={active === 'chat'} />
        </TouchableOpacity>
      </View>

      <View style={[styles.rightNav, { 
        right: Math.max(20, screenWidth * 0.075), // At least 20px, or 7.5% of screen width
        width: Math.min(109, screenWidth * 0.28) // At most 109px, or 28% of screen width
      }]}>
        <TouchableOpacity style={styles.iconBtn} onPress={() => handlePress('camera')}>
          <CameraIcon active={active === 'camera'} />
        </TouchableOpacity>
        <TouchableOpacity style={styles.iconBtn} onPress={() => handlePress('phrasebook')}>
          <PhrasebookIcon active={active === 'phrasebook'} />
        </TouchableOpacity>
      </View>

      <View style={[styles.micContainer, { 
        left: (screenWidth / 2) - (MIC_SIZE / 2)
      }]}>
        <MicGlow />
        <TouchableOpacity style={styles.micButton} onPress={() => handlePress('mic')}>
          <MicSvgIcon active={active === 'mic'} />
        </TouchableOpacity>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    height: FOOTER_HEIGHT,
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    paddingHorizontal: 0,
    marginHorizontal: 0,
    backgroundColor: 'transparent',
    zIndex: 10,
    width: '100%',
  },
  leftNav: {
    position: 'absolute',
    top: 49,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  rightNav: {
    position: 'absolute',
    top: 49,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  iconBtn: {
    width: 44, // Fixed size for icons, can be made responsive with libraries if needed
    height: 44,
    borderRadius: 22,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'transparent',
    opacity: 0.8,
  },
  micContainer: {
    position: 'absolute',
    top: -MIC_SIZE / 2 + 21,
    width: MIC_SIZE,
    height: MIC_SIZE, 
    alignItems: 'center', 
    justifyContent: 'center',
    zIndex: 20,
  },
  micButton: {
    position: 'absolute',
    width: MIC_SIZE,
    height: MIC_SIZE, 
    borderRadius: MIC_SIZE / 2,
    backgroundColor: ORANGE,
    justifyContent: 'center', 
    alignItems: 'center',
    shadowColor: ORANGE,
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 12,
    elevation: 8,
  },
});

export default Footer;