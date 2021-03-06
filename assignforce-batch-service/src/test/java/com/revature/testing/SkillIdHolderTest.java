package com.revature.testing;

import static org.junit.Assert.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.revature.assignforce.beans.SkillIdHolder;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest
public class SkillIdHolderTest {

	@Configuration
	static class SkillIdHolderTestContextConfiguration {
	@Bean
	public SkillIdHolder SkillIdHolder() {
		return new SkillIdHolder();
		}
	}
	
	@Test
	public void skillIdHolderTest1() {
		SkillIdHolder s1 = new SkillIdHolder();
		assertNotNull(s1);
	}
	
	@Test
	public void skillIdHolderTest2() {
		SkillIdHolder s1 = new SkillIdHolder(4);
		//assertTrue(s1.getId() == 4);
		assertEquals(4, s1.getId());
	}
	
	@Test
	public void getSetSkillIdTest() {
		SkillIdHolder s1 = new SkillIdHolder();
		s1.setSkillID(39);
		//assertTrue(s1.getId() == 39);
		assertEquals(39, s1.getId());
	}

}
