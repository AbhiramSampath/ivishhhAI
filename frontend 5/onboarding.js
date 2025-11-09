import React, { useState, useRef, useEffect } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  Dimensions,
  StyleSheet,
  StatusBar,
  Image,
  FlatList,
  Animated,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import { completeOnboarding } from './api';

const { width, height } = Dimensions.get('window');

// Image and spacing constants
const IMAGE_WIDTH = width * 0.8;
const IMAGE_HEIGHT = IMAGE_WIDTH * 1.2;
const SPACING = 20;

// Onboarding data with Unsplash images
const onboardingData = [
  {
    id: 1,
    title: "Speak in your language, they'll hear theirs",
    subtitle: "Live dual-language captions + AI voice modulation.",
    image: "https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?w=400&h=600&fit=crop&crop=face",
  },
  {
    id: 2,
    title: "See, hear, and feel understood", 
    subtitle: "Face-to-face communication, translated in real time.",
    image: "https://images.unsplash.com/photo-1607990281513-2c110a25bd8c?w=400&h=600&fit=crop",
  },
  {
    id: 3,
    title: "AI that understands how you speak",
    subtitle: "Tone-matched responses + helpful suggestions mid-conversation.",
    image: "https://images.unsplash.com/photo-1485827404703-89b55fcc595e?w=400&h=600&fit=crop",
  },
];

const SplashOnboarding = () => {
  const navigation = useNavigation();
  const [currentIndex, setCurrentIndex] = useState(0);
  const flatListRef = useRef(null);
  const scrollX = useRef(new Animated.Value(0)).current;

  const handleGetStarted = async () => {
    try {
      await completeOnboarding('dummy_user_id', 'device_fingerprint_placeholder', 'zkp_proof_placeholder');
      navigation.navigate('Home');
    } catch (error) {
      console.error('Onboarding completion failed:', error);
      navigation.navigate('Home'); // Still navigate
    }
  };

  const handleSkip = () => {
    navigation.navigate('Home');
  };

  const handleNext = () => {
    if (currentIndex < onboardingData.length - 1) {
      const nextIndex = currentIndex + 1;
      flatListRef.current?.scrollToIndex({ index: nextIndex, animated: true });
      setCurrentIndex(nextIndex);
    } else {
      handleGetStarted();
    }
  };

  const onViewableItemsChanged = useRef(({ viewableItems }) => {
    if (viewableItems.length > 0) {
      setCurrentIndex(viewableItems[0].index);
    }
  }).current;

  const viewabilityConfig = useRef({
    itemVisiblePercentThreshold: 50,
  }).current;

  const renderItem = ({ item, index }) => {
    return (
      <View style={styles.imageContainer}>
        <Image
          source={{ uri: item.image }}
          style={styles.carouselImage}
          resizeMode="cover"
        />
      </View>
    );
  };

  const renderDots = () => {
    return (
      <View style={styles.dotsContainer}>
        {onboardingData.map((_, index) => (
          <View
            key={index}
            style={[
              styles.dot,
              { opacity: index === currentIndex ? 1 : 0.3 }
            ]}
          />
        ))}
      </View>
    );
  };

  const isLastScreen = currentIndex === onboardingData.length - 1;
  const currentData = onboardingData[currentIndex];

  return (
    <View style={styles.container}>
      <StatusBar barStyle="dark-content" backgroundColor="#BFC5F5" />
      
      {/* Skip Button */}
      <TouchableOpacity style={styles.skipButton} onPress={handleSkip}>
        <Text style={styles.skipText}>Skip</Text>
      </TouchableOpacity>

      {/* Carousel */}
      <View style={styles.carouselContainer}>
        <Animated.FlatList
          ref={flatListRef}
          data={onboardingData}
          renderItem={renderItem}
          horizontal
          pagingEnabled
          showsHorizontalScrollIndicator={false}
          keyExtractor={(item) => item.id.toString()}
          onScroll={Animated.event(
            [{ nativeEvent: { contentOffset: { x: scrollX } } }],
            { useNativeDriver: false }
          )}
          onViewableItemsChanged={onViewableItemsChanged}
          viewabilityConfig={viewabilityConfig}
          snapToInterval={IMAGE_WIDTH + SPACING}
          decelerationRate="fast"
          contentContainerStyle={{
            paddingHorizontal: (width - IMAGE_WIDTH) / 2,
          }}
          ItemSeparatorComponent={() => <View style={{ width: SPACING }} />}
        />
      </View>

      {/* Dots Indicator */}
      {renderDots()}

      {/* Content Section */}
      <View style={styles.contentContainer}>
        <Text style={styles.title}>{currentData.title}</Text>
        <Text style={styles.subtitle}>{currentData.subtitle}</Text>
      </View>

      {/* Bottom Button */}
      <View style={styles.bottomButtonContainer}>
        <TouchableOpacity 
          style={[styles.button, isLastScreen && styles.getStartedButton]} 
          onPress={isLastScreen ? handleGetStarted : handleNext}
        >
          <Text style={[styles.buttonText, isLastScreen && styles.getStartedButtonText]}>
            {isLastScreen ? 'Get Started' : 'Next'}
          </Text>
          {!isLastScreen && <Text style={styles.nextButtonArrow}>→</Text>}
        </TouchableOpacity>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#BFC5F5',
  },
  skipButton: {
    position: 'absolute',
    top: (StatusBar.currentHeight || 40) + 10,
    right: 20,
    zIndex: 10,
    paddingHorizontal: 15,
    paddingVertical: 8,
  },
  skipText: {
    fontSize: 16,
    color: '#666',
    fontWeight: '500',
  },
  carouselContainer: {
    marginTop: (StatusBar.currentHeight || 40) + 60,
    height: IMAGE_HEIGHT,
  },
  imageContainer: {
    width: IMAGE_WIDTH,
    height: IMAGE_HEIGHT,
    borderRadius: 20,
    overflow: 'hidden',
    backgroundColor: '#fff',
    elevation: 8,
    shadowColor: '#000',
    shadowOffset: {
      width: 0,
      height: 4,
    },
    shadowOpacity: 0.2,
    shadowRadius: 8,
  },
  carouselImage: {
    width: '100%',
    height: '100%',
  },
  dotsContainer: {
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    marginTop: 30,
    marginBottom: 20,
  },
  dot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: '#333',
    marginHorizontal: 4,
  },
  contentContainer: {
    paddingHorizontal: 40,
    alignItems: 'center',
    marginTop: 20,
    flex: 1,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#333',
    textAlign: 'center',
    marginBottom: 12,
    lineHeight: 34,
  },
  subtitle: {
    fontSize: 16,
    color: '#666',
    textAlign: 'center',
    lineHeight: 24,
    paddingHorizontal: 10,
  },
  bottomButtonContainer: {
    paddingHorizontal: 40,
    paddingBottom: 50,
  },
  button: {
    backgroundColor: 'rgba(255, 255, 255, 0.9)',
    borderRadius: 25,
    paddingVertical: 16,
    paddingHorizontal: 30,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    elevation: 3,
    shadowColor: '#000',
    shadowOffset: {
      width: 0,
      height: 2,
    },
    shadowOpacity: 0.1,
    shadowRadius: 4,
  },
  getStartedButton: {
    backgroundColor: '#0C0D11',
  },
  buttonText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#333',
    marginRight: 8,
  },
  getStartedButtonText: {
    color: '#FFFFFF',
    marginRight: 0,
  },
  nextButtonArrow: {
    fontSize: 16,
    color: '#333',
    fontWeight: 'bold',
  },
});

export default SplashOnboarding;
